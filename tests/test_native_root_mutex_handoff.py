"""Deterministic fault simulation; this does not execute Windows APIs."""
from contextlib import ExitStack
from dataclasses import replace
import threading
import unittest
from unittest.mock import patch

from phase_tool.errors import PhaseError
from phase_tool.mutation.ntfs import root_lock as locks
from phase_tool.mutation.ntfs.native import NativeIO, NativeIdentity
from phase_tool.mutation.ntfs.scoped import NativeRootGrant


class Function:
    def __init__(self, callback):
        self.callback = callback

    def __call__(self, *arguments):
        return self.callback(*arguments)


class Scope:
    def __init__(self, *arguments):
        pass

    def assert_bound(self):
        pass

    def close(self):
        pass


class HandoffTests(unittest.TestCase):
    def test_unprintable_release_failure_does_not_interrupt_close_scope_or_retire(self):
        events=[]
        class Broken(Exception):
            def __str__(self):raise RuntimeError('synthetic diagnostic failure')
        class TrackedScope(Scope):
            def close(self):events.append('scope')
        def release(*_):
            events.append('release');raise Broken()
        def close(*_):events.append('close');return 1
        kernel=type('Kernel',(),{})()
        for name,callback in [('CreateMutexExW',lambda *_:1),('WaitForSingleObject',lambda *_:0),
                              ('ReleaseMutex',release),('CloseHandle',close)]:
            setattr(kernel,name,Function(callback))
        grant=NativeRootGrant('phase_result_root',r'\Device\HarddiskVolume6',
            '\\\\?\\volume{00000000-0000-0000-0000-000000000001}\\',42,
            ('synthetic-broken-error',),NativeIdentity(42,'ce'*16))
        io=object.__new__(NativeIO);io.kernel=kernel
        lock=locks.NativeRootMutex(io,grant)
        with ExitStack() as stack:
            stack.enter_context(patch.object(locks,'NativeScopedTarget',TrackedScope))
            stack.enter_context(patch.object(locks.C,'set_last_error',lambda _:None,create=True))
            stack.enter_context(patch.object(locks.C,'get_last_error',lambda:5,create=True))
            try:
                with self.assertRaisesRegex(PhaseError,'ntfs.root_lock_finalization_failed') as raised:
                    with lock:raise PhaseError('synthetic.body_failure')
                self.assertEqual(events,['release','close','scope'])
                self.assertEqual(lock.state,'unknown')
                self.assertEqual(raised.exception.details['primary_error']['code'],'synthetic.body_failure')
                with locks._REGISTRY_GUARD:
                    self.assertNotIn(lock._key,locks._ACTIVE)
                    self.assertIn((locks.os.getpid(),lock.name),locks._QUARANTINED)
                self.assertIsInstance(lock.events[-2]['call_error'],dict)
            finally:
                with locks._REGISTRY_GUARD:
                    locks._QUARANTINED.discard((locks.os.getpid(),lock.name))

    def test_already_waiting_owner_cannot_escape_unknown_release_quarantine(self):
        holder_ready, waiting, released, returned = (threading.Event() for _ in range(4))
        result, events, serial = {}, [], [0]
        grant = NativeRootGrant('phase_result_root', r'\Device\HarddiskVolume6',
            '\\\\?\\volume{00000000-0000-0000-0000-000000000001}\\', 42,
            ('qualification',), NativeIdentity(42, 'ab'*16))

        def create(*arguments):
            serial[0] += 1
            return serial[0]

        def wait(handle, timeout):
            if handle == 1:
                return 0
            waiting.set()
            if not released.wait(3):
                raise RuntimeError('simulated release barrier absent')
            returned.set()  # Wait result is available before the old owner's close/retire.
            return 0

        def release(handle):
            events.append(('release', handle))
            if handle == 1:
                released.set()
                if not returned.wait(3):
                    raise RuntimeError('simulated waiter result absent')
                return 0  # Explicit injected ReleaseMutex failure; not a real OS result.
            return 1

        def close(handle):
            events.append(('close', handle))
            return 1

        kernel = type('Kernel', (), {})()
        for name, function in [('CreateMutexExW', create), ('WaitForSingleObject', wait),
                               ('ReleaseMutex', release), ('CloseHandle', close)]:
            setattr(kernel, name, Function(function))

        def owner(kind):
            io = object.__new__(NativeIO)
            io.kernel = kernel
            lock = locks.NativeRootMutex(io, grant)
            try:
                with lock:
                    if kind == 'holder':
                        holder_ready.set()
                        if not waiting.wait(3):
                            raise RuntimeError('simulated waiter absent')
                    else:
                        result['waiter_usable'] = True
            except BaseException as error:
                result[kind] = error
            result[kind + '_events'] = lock.events
            result[kind + '_state'] = lock.state

        # The native type boundary remains exercised; only the OS and existing
        # root pin are simulated. No filesystem fixture or Windows call occurs.
        with ExitStack() as stack:
            stack.enter_context(patch.object(locks, 'NativeScopedTarget', Scope))
            stack.enter_context(patch.object(locks.C, 'set_last_error', lambda value: None, create=True))
            stack.enter_context(patch.object(locks.C, 'get_last_error', lambda: 5, create=True))
            holder = threading.Thread(target=owner, args=('holder',))
            waiter = threading.Thread(target=owner, args=('waiter',))
            try:
                holder.start()
                self.assertTrue(holder_ready.wait(3))
                waiter.start()
                holder.join(5)
                waiter.join(5)
                self.assertFalse(holder.is_alive() or waiter.is_alive())
                self.assertNotIn('waiter_usable', result)
                self.assertIsInstance(result['holder'], PhaseError)
                self.assertEqual(result['holder'].code, 'ntfs.root_lock_finalization_unknown')
                self.assertIsInstance(result['waiter'], PhaseError)
                self.assertEqual(result['waiter'].code, 'ntfs.root_lock_worker_quarantined')
                self.assertEqual(result['holder_state'], 'unknown')
                self.assertEqual(result['waiter_state'], 'closed')
                self.assertEqual(events, [('release', 1), ('close', 1), ('release', 2), ('close', 2)])
                self.assertEqual([event['result'] for event in result['waiter_events']
                                  if event['api'] == 'WaitForSingleObject'], [0])
                io = object.__new__(NativeIO)
                io.kernel = kernel
                third = locks.NativeRootMutex(io, replace(grant, binding='same_root_alias'))
                with self.assertRaisesRegex(PhaseError, 'ntfs.root_lock_worker_quarantined'):
                    third.acquire()
                self.assertEqual(third.events, [])
            finally:
                # Unblock and join our own simulation threads even on assertion
                # failure. Never clear production registry entries or other roots.
                released.set()
                returned.set()
                waiting.set()
                if holder.ident:
                    holder.join(5)
                if waiter.ident:
                    waiter.join(5)
                with locks._REGISTRY_GUARD:
                    locks._QUARANTINED.discard((locks.os.getpid(), locks.root_mutex_name(grant)))


if __name__ == '__main__':
    unittest.main()
