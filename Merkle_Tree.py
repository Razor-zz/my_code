# Hash
# • Merkle proof
# • Implement Merkle Tree as of RFC 6962 in any programming language that you prefer
# • Construct a merkle tree with 100k leaf nodes
# • Construct the existence (inclusion) proof for randomly chosen leaf node & verify the proof
#qwe

import hashlib 
import random 

def _leaf_hash(leaf):
    return  hashlib.sha256(b"\x00" + leaf).digest()
def _pair_hash( left, right):
    return  hashlib.sha256(b"\x01" + left + right).digest()
class InclusionProof:
    """
    Represents a Merkle inclusion proof for purposes of serialization,
    deserialization, and verification of the proof.  The format for inclusion
    proofs in RFC 6962-bis is as follows:
        opaque LogID<2..127>;
        opaque NodeHash<32..2^8-1>;
        struct {
            LogID log_id;
            uint64 tree_size;
            uint64 leaf_index;
            NodeHash inclusion_path<1..2^16-1>;
        } InclusionProofDataV2;
    In other words:
      - 1 + N octets of log_id (currently zero)
      - 8 octets of tree_size = self.n
      - 8 octets of leaf_index = m
      - 2 octets of path length, followed by
      * 1 + N octets of NodeHash
    """

    # Pre-generated 'log ID'.  Not used by Firefox; it is only needed because
    # there's a slot in the RFC 6962-bis format that requires a value at least
    # two bytes long (plus a length byte).
    LOG_ID = b"\x02\x00\x00"

    def __init__(self, tree_size, leaf_index, path_elements):
        self.tree_size = tree_size
        self.leaf_index = leaf_index
        self.path_elements = path_elements
    def _expected_head(self, leaf, leaf_index, tree_size):
        node = _leaf_hash(leaf)
        # Compute indicators of which direction the pair hashes should be done.
        # Derived from the PATH logic in draft-ietf-trans-rfc6962-bis
        lr = []
        while tree_size > 1:
            k = 1
            while k < end - begin:
                k <<= 1
            k=k >> 1   #递归定义
            left = leaf_index < k
            lr = [left] + lr

            if left:
                tree_size = k
            else:
                tree_size = tree_size - k
                leaf_index = leaf_index - k

        assert len(lr) == len(self.path_elements)
        for i, elem in enumerate(self.path_elements):
            if lr[i]:
                node = _pair_hash(node, elem)
            else:
                node = _pair_hash( elem, node)

        return node  #根节点

    def verify(self,  leaf, leaf_index, tree_size, tree_head):
        return self._expected_head( leaf, leaf_index, tree_size) == tree_head


class MerkleTree:
    """
    according to rfc 6926
    """
    def __init__(self, data):
        self.n = len(data)
        self.nodes = {}
        for i in range(self.n):
            self.nodes[i, i + 1] = _leaf_hash(data[i])   #rfc6926,use D[m,n]d enote d[m] to d[n-1],head is   nodes[0][n].

    def _node(self, begin, end):
        if (begin, end) in self.nodes:
            return self.nodes[begin, end]
        k = 1
        while k < end - begin:
            k <<= 1
        k=k >> 1   #递归定义
        left = self._node(begin, begin + k)
        right = self._node(begin + k, end)
        node = _pair_hash(left, right)
        self.nodes[begin, end] = node
        return node
    def head(self):
        return self._node(0, self.n)

    def _relative_proof(self, target, begin, end):
        n = end - begin
        k = 1
        while k < end - begin:
            k <<= 1
        k=k >> 1   #递归定义
        if n == 1:
            return []
        elif target - begin < k:   #在k的左边，+上右边的hahs 
            return self._relative_proof(target, begin, begin + k) + [self._node(begin + k, end)] 
        elif target - begin >= k:
            return self._relative_proof(target, begin + k, end) + [self._node(begin, begin + k)] 
    def inclusion_proof(self, leaf_index):
        path_elements = self._relative_proof(leaf_index, 0, self.n)  #路径
        return InclusionProof(self.n, leaf_index, path_elements)



TEST_SIZE = 5000   ##实验要100k
ELEM_SIZE_BYTES = 16
data = [bytearray(random.getrandbits(8) for _ in range(ELEM_SIZE_BYTES))for _ in range(TEST_SIZE)]
tree = MerkleTree(data)
head = tree.head()
for i in range(len(data)):
    proof = tree.inclusion_proof(i)

    self.assertTrue(proof.verify(data[i], i, len(data), head))
    self.assertEqual(proof.leaf_index, i)
    self.assertEqual(proof.tree_size, tree.n)