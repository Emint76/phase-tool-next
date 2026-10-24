"""RO component ordering with synthetic handles; not Windows qualification.

The NativeIO constructor is replaced by an allocated synthetic IO instance; no
Windows API, target mutation or qualification guard is executed or bypassed.
The actual scope/hash/decoder code operates over an explicitly synthetic
in-memory namespace and actual NativeHandle finalizers. Run in Linux CI only;
final source review is required before execution.
"""
from copy import deepcopy
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from phase_tool.canonical import digest_bytes
from phase_tool.errors import PhaseError
from phase_tool.mutation.ntfs import file_create, native, scoped, version1_observation
from phase_tool.mutation.ntfs.mutating import NativeMutationIO


class _SyntheticTree:
    def __init__(self, relative_dirs=(), content=None, *, links=1):
        self.io = object.__new__(native.NativeIO)
        self.io._handles = {}
        self.io.kernel = SimpleNamespace(CloseHandle=self.close)
        self.grant = scoped.NativeRootGrant('fixture_result_root',r'\Device\HarddiskVolume6',
            '\\\\?\\volume{00000000-0000-0000-0000-000000000001}\\',42,
            ('qualification','synthetic'),native.NativeIdentity(42,'03'*16))
        self.root = self.grant.components
        self.nodes = {():native.NativeIdentity(42,'01'*16),
            self.root[:1]:native.NativeIdentity(42,'02'*16),self.root:self.grant.root_identity}
        for number,path in enumerate(relative_dirs,4):
            self.nodes[self.root+tuple(path.split('/'))] = native.NativeIdentity(42,f'{number:02x}'*16)
        self.content,self.links = content,links
        if content is not None:
            self.nodes[self.root+('current.bin',)] = native.NativeIdentity(42,'20'*16)
        self.paths,self.failures,self.calls,self.hash_chunks = {},{},[],0
        self.counter = 100
        self.io.volume = self.volume
        self.io.open_device_root = self.open_root
        self.io.child = self.child
        self.io._open = self.open_name
        self.io.identity = self.identity
        self.io.info = self.info
        self.io.assert_object = self.assert_object
        self.io.read_chunks = self.read_chunks

    def volume(self):
        return {'device':self.grant.device,'volume_guid':self.grant.volume_guid,
            'volume_serial32':42,'filesystem':'NTFS'}

    def adopt(self, path, directory):
        self.counter += 1
        handle = self.io._adopt(self.counter,directory=directory)
        self.paths[handle.value] = (path,self.nodes[path])
        return handle

    def close(self, value):
        self.calls.append(('close',value))
        return 1

    def open_root(self, volume):
        if volume != self.volume():
            raise AssertionError('synthetic volume mismatch')
        return self.adopt((),True)

    def open_name(self, name, *, parent, directory, sharing=3, **kwargs):
        return self.child(parent,name,directory=directory,**kwargs)

    def child(self, parent, name, *, directory, **kwargs):
        self.io._live(parent)
        path = self.paths[parent.value][0]+(name,)
        self.calls.append(('open',path,directory))
        if path in self.failures:
            raise self.failures[path]
        if path not in self.nodes:
            raise PhaseError('ntfs.open_failed',details={'ntstatus':'0xc0000034'})
        if directory is (path == self.root+('current.bin',)):
            raise PhaseError('ntfs.object_type_mismatch')
        return self.adopt(path,directory)

    def identity(self, handle):
        self.io._live(handle)
        return self.paths[handle.value][1]

    def info(self, handle):
        self.io._live(handle)
        return {'attributes':0x10 if handle.directory else 0,
            'length':0 if handle.directory else len(self.content),'links':self.links}

    def assert_object(self, handle, *, directory=None, expected=None):
        self.io._live(handle)
        if directory is not None and handle.directory is not directory:
            raise PhaseError('ntfs.object_type_mismatch')
        if expected is not None and self.identity(handle) != expected:
            raise PhaseError('ntfs.object_identity_mismatch')
        return self.info(handle)

    def read_chunks(self, handle, maximum):
        self.io._live(handle)
        if len(self.content) > maximum:
            raise PhaseError('ntfs.read_limit')
        for offset in range(0,len(self.content),1024**2):
            self.hash_chunks += 1
            yield self.content[offset:offset+1024**2]


class NativeVersion1ObservationTests(unittest.TestCase):
    def observe(self, tree, locator='current.bin', **kwargs):
        with patch.object(version1_observation,'NativeIO',return_value=tree.io):
            return version1_observation.observe_version1_file(tree.grant,locator,**kwargs)

    def test_missing_relative_prefixes_retain_real_prefix_identity(self):
        locator = 'archive/sha256/ab/object.bin'
        for existing in ((),('archive',),('archive','archive/sha256'),
                         ('archive','archive/sha256','archive/sha256/ab')):
            with self.subTest(existing=existing):
                tree = _SyntheticTree(existing)
                response = self.observe(tree,locator)
                self.assertFalse(response['state']['exists'])
                self.assertEqual(response['native'],{'exists':False,'native_identity':None})
                prefix = response['ancestor_absence']
                if len(existing) == 3:
                    self.assertIsNone(prefix)
                else:
                    parts = locator.split('/')
                    self.assertEqual(prefix['existing_relative_components'],parts[:len(existing)])
                    self.assertEqual(prefix['missing_relative_components'],parts[len(existing):])
                    self.assertEqual(prefix['existing_parent_identity'],
                        tree.nodes[tree.root+tuple(parts[:len(existing)])].as_dict())
                self.assertEqual(tree.io._handles,{})
                self.assertTrue(all(item[0] in ('open','close') for item in tree.calls))

    def test_missing_granted_root_never_becomes_relative_absence(self):
        for path in (('qualification',),('qualification','synthetic')):
            with self.subTest(path=path):
                tree = _SyntheticTree()
                del tree.nodes[path]
                with self.assertRaisesRegex(PhaseError,'ntfs.open_failed'):
                    self.observe(tree,'archive/object.bin')
                self.assertEqual(tree.io._handles,{})

    def test_default_scope_and_nonmissing_errors_remain_refusals(self):
        tree = _SyntheticTree()
        with self.assertRaisesRegex(PhaseError,'ntfs.open_failed'):
            scoped.NativeScopedTarget(tree.io,tree.grant,'archive/object.bin')
        self.assertEqual(tree.io._handles,{})
        for error in (PhaseError('ntfs.open_failed',details={'ntstatus':'0xc0000022'}),
                      PhaseError('ntfs.open_failed',details={'ntstatus':'0xc000003a'}),
                      PhaseError('ntfs.open_failed',details={'ntstatus':'0xc0000034','extra':True}),
                      PhaseError('ntfs.reparse_forbidden'),PhaseError('ntfs.object_type_mismatch')):
            with self.subTest(error=error.code,details=error.details):
                tree = _SyntheticTree()
                tree.failures[tree.root+('archive',)] = error
                with self.assertRaises(PhaseError) as caught:
                    self.observe(tree,'archive/object.bin')
                self.assertIs(caught.exception,error)
                self.assertEqual(tree.io._handles,{})

    def test_partial_scope_is_read_only_and_cannot_open_a_leaf(self):
        tree = _SyntheticTree()
        with scoped.NativeScopedTarget(tree.io,tree.grant,'archive/object.bin',
                                      _allow_missing_ancestors=True) as scope:
            with self.assertRaisesRegex(PhaseError,'ntfs.partial_scope_has_no_leaf_parent'):
                scope.open_file()
            with self.assertRaisesRegex(PhaseError,'ntfs.partial_scope_has_no_leaf_parent'):
                scope.assert_file_name(scope.parent,scope.parent_identity)
        for io,flush in ((object.__new__(NativeMutationIO),False),(tree.io,True)):
            with self.subTest(mutating=type(io) is NativeMutationIO,flush=flush):
                with self.assertRaisesRegex(PhaseError,'ntfs.partial_scope_read_only_required'):
                    scoped.NativeScopedTarget(io,tree.grant,'archive/object.bin',
                        namespace_flush=flush,_allow_missing_ancestors=True)

    def test_missing_ancestor_appearing_or_prefix_rebinding_is_not_absence(self):
        for action in ('appear','rebind'):
            tree = _SyntheticTree()
            with scoped.NativeScopedTarget(tree.io,tree.grant,'archive/object.bin',
                                          _allow_missing_ancestors=True) as scope:
                if action == 'appear':
                    tree.nodes[tree.root+('archive',)] = native.NativeIdentity(42,'21'*16)
                else:
                    tree.nodes[tree.root] = native.NativeIdentity(42,'22'*16)
                code = 'ntfs.missing_ancestor_appeared' if action == 'appear' else 'ntfs.object_identity_mismatch'
                with self.assertRaisesRegex(PhaseError,code):
                    scope.ancestor_absence()
            self.assertEqual(tree.io._handles,{})

    def test_full_content_hash_includes_tail_above_original_one_mib(self):
        for content in (b'',b'a'*1024**2,b'a'*1024**2+b'z',b'a'*(16*1024**2-1)+b'z'):
            with self.subTest(length=len(content)):
                tree = _SyntheticTree(content=content)
                result = self.observe(tree)
                self.assertIs(result['state']['exists'],True)
                self.assertEqual(result['state']['digest'],digest_bytes(content))
                self.assertEqual(result['state']['length'],len(content))
                self.assertEqual(tree.hash_chunks,(len(content)+1024**2-1)//1024**2)
                self.assertEqual(result['native']['native_identity'],native.NativeIdentity(42,'20'*16).as_dict())
                self.assertIsNone(result['ancestor_absence'])
                self.assertEqual(tree.io._handles,{})

    def test_oversize_wrong_identity_and_detected_links_refuse(self):
        for content,links,expected in ((b'x'*(16*1024**2+1),1,None),
                                       (b'x',2,None),(b'x',1,native.NativeIdentity(42,'23'*16))):
            with self.subTest(length=len(content),links=links,expected=expected):
                tree = _SyntheticTree(content=content,links=links)
                with self.assertRaises(PhaseError):
                    self.observe(tree,expected=expected)
                self.assertEqual(tree.io._handles,{})
                if len(content) > 16*1024**2:
                    self.assertEqual(tree.hash_chunks,0)

    def test_existing_file_create_observation_keeps_original_bound_and_shape(self):
        tree = _SyntheticTree(content=b'a'*(1024**2+1))
        with patch.object(file_create,'NativeIO',return_value=tree.io):
            response = file_create.observe_file(tree.grant,'current.bin')
        self.assertEqual(response['observation_version'],'1.0')
        self.assertNotIn('ancestor_absence',response)
        self.assertIsNone(response['state']['digest'])
        self.assertEqual(tree.hash_chunks,0)
        self.assertEqual(tree.io._handles,{})

    def test_expected_identity_never_matches_leaf_or_ancestor_absence(self):
        for locator in ('absent.bin','archive/absent.bin'):
            tree = _SyntheticTree()
            with self.assertRaisesRegex(PhaseError,'ntfs.expected_file_absent'):
                self.observe(tree,locator,expected=native.NativeIdentity(42,'24'*16))
            self.assertEqual(tree.io._handles,{})

    def test_decoder_rejects_old_partial_unhashed_or_mixed_identity_inputs(self):
        tree = _SyntheticTree(content=b'payload')
        original = self.observe(tree)
        changes = ((('observation_version',),'1.0'),(('handles_finalized',),False),
            (('native','link_count'),True),(('native','link_count'),2),
            (('native','length'),True),(('state','length'),True),
            (('native','native_identity'),native.NativeIdentity(43,'20'*16).as_dict()),
            (('state','digest'),None),(('native','digest'),'sha256:'+'0'*64),
            (('ancestor_absence',),{}),(('extra',),True))
        for keys,value in changes:
            with self.subTest(keys=keys,value=value):
                raw = deepcopy(original)
                target = raw if len(keys) == 1 else raw[keys[0]]
                target[keys[-1]] = value
                with self.assertRaises(PhaseError):
                    version1_observation.validate_version1_observation(raw,tree.grant.as_dict(),'current.bin')
        restored = version1_observation.validate_version1_observation(original,tree.grant.as_dict(),'current.bin')
        restored['native']['native_identity']['file_id'] = '00'*16
        self.assertEqual(original['native']['native_identity']['file_id'],'20'*16)

    def test_absence_decoder_requires_exact_suffix_and_real_prefix_identity(self):
        tree = _SyntheticTree()
        original = self.observe(tree,'archive/sha256/object.bin')
        for key,value in (('existing_relative_components',['wrong']),
                          ('missing_relative_components',['object.bin']),
                          ('existing_parent_identity',native.NativeIdentity(42,'25'*16).as_dict()),
                          ('existing_parent_identity',native.NativeIdentity(43,'03'*16).as_dict())):
            with self.subTest(key=key,value=value):
                raw = deepcopy(original)
                raw['ancestor_absence'][key] = value
                with self.assertRaises(PhaseError):
                    version1_observation.validate_version1_observation(raw,tree.grant.as_dict(),'archive/sha256/object.bin')

    def test_scope_initialization_close_failure_retains_the_primary_wrapper(self):
        tree = _SyntheticTree()
        with patch.object(native.NativeHandle,'close',side_effect=OSError('synthetic close failure')):
            with self.assertRaisesRegex(PhaseError,'ntfs.scope_initialization_finalization_failed'):
                self.observe(tree,'archive/object.bin')
        self.assertTrue(tree.io._handles)

    def test_scope_finalization_failure_never_emits_a_finalized_observation(self):
        tree = _SyntheticTree()
        original = scoped.NativeScopedTarget.ancestor_absence
        def arm_after_successful_read(scope):
            result = original(scope)
            # No more opens occur on this missing-ancestor branch. Fail only
            # the real post-body scope.close, after successful construction
            # and absence recheck, not an initialization temporary close.
            tree.io.kernel.CloseHandle = fail_close
            return result
        def fail_close(value):
            raise OSError('synthetic post-body close failure')
        with patch.object(scoped.NativeScopedTarget,'ancestor_absence',arm_after_successful_read):
            with self.assertRaisesRegex(PhaseError,'ntfs.scope_finalization_failed'):
                self.observe(tree,'archive/object.bin')
        self.assertTrue(tree.io._handles)


if __name__ == '__main__':
    unittest.main()
