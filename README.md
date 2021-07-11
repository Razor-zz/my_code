merkle 树介绍
数据存储在叶节点，非叶节点存储散列
node = hash $\Sigma i$(node.children(i).hash )

## RFC6926定义：

hash是sha256,

```
   Structure of the Merkle Tree input:

       enum { timestamped_entry(0), (255) }
         MerkleLeafType;

       struct {
           uint64 timestamp;
           LogEntryType entry_type;
           select(entry_type) {
               case x509_entry: ASN.1Cert;
               case precert_entry: PreCert;
           } signed_entry;
           CtExtensions extensions;
       } TimestampedEntry;

       struct {
           Version version;
           MerkleLeafType leaf_type;
           select (leaf_type) {
               case timestamped_entry: TimestampedEntry;
           }
       } MerkleTreeLeaf;
```

输出32字节默克尔树hahs，给定d0--dn-1。。

叶子：MTH({d(0)}) = SHA-256(0x00 || d(0)).

内节点是:MTH(D[n]) = SHA-256(0x01 || MTH(D[0:k]) || MTH(D[k:n])),