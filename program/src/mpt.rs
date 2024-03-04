//! This module contains a verification function for Merkle Patricia Trie proofs.

use alloy_rlp::{Decodable, Error as RlpError};
use reth_primitives::{keccak256, Bytes, B256};

/// The number of elements per branch node.
const TREE_RADIX: usize = 16;

/// Branch nodes have [TREE_RADIX] elements and one value elements.
const BRANCH_NODE_LENGTH: usize = TREE_RADIX + 1;

/// Leaf nodes and extension nodes have two elements, a `path` and a `value`.
const LEAF_OR_EXTENSION_NODE_LENGTH: usize = 2;

/// Prefix for even-nibbled extension node paths.
const PREFIX_EXTENSION_EVEN: u8 = 0;

/// Prefix for odd-nibbled extension node paths.
const PREFIX_EXTENSION_ODD: u8 = 1;

/// Prefix for even-nibbled leaf node paths.
const PREFIX_LEAF_EVEN: u8 = 2;

/// Prefix for odd-nibbled leaf node paths.
const PREFIX_LEAF_ODD: u8 = 3;

/// A [TrieNode] is a node in a Merkle Patricia Trie. This structure contains both the RLP encoded and decoded forms of
/// the node.
pub(crate) struct TrieNode<'a> {
    pub(crate) encoded: &'a Bytes,
    pub(crate) decoded: Vec<Bytes>,
}

impl<'a> TrieNode<'a> {
    pub(crate) fn try_new(encoded: &'a Bytes) -> Result<Self, RlpError> {
        let decoded = Decodable::decode(&mut &encoded[..])?;
        Ok(Self { encoded, decoded })
    }
}

/// Get the value for a key from a Merkle Patricia Trie proof.
pub(crate) fn get(key: &Bytes, proof: &Vec<Bytes>, root: B256) -> Result<Bytes, RlpError> {
    if key.len() == 0 {
        return Err(RlpError::Custom("Invalid key length"));
    }

    let key = to_nibbles(&key);
    let mut current_node_id: Bytes = root.into();
    let mut current_key_index = 0;

    for i in 0..proof.len() {
        let TrieNode {
            encoded: encoded_node,
            decoded: decoded_node,
        } = TrieNode::try_new(proof.get(i).ok_or(RlpError::Custom("Out of bounds"))?)?;

        if current_key_index > key.len() {
            return Err(RlpError::Custom("Invalid key index"));
        } else if current_key_index == 0 {
            // The first proof element is always the root node
            if keccak256(encoded_node).as_slice() != current_node_id.as_ref() {
                return Err(RlpError::Custom("Invalid root"));
            }
        } else if encoded_node.len() >= 32 {
            if keccak256(encoded_node).as_slice() != current_node_id.as_ref() {
                return Err(RlpError::Custom("Invalid large internal hash"));
            }
        } else if encoded_node != current_node_id.as_ref() {
            return Err(RlpError::Custom("Invalid internal node hash"));
        }

        if decoded_node.len() == BRANCH_NODE_LENGTH {
            if current_key_index == key.len() {
                // Value is the last element of the decoded list (for branch nodes). There's
                // some ambiguity in the Merkle trie specification because bytes(0) is a
                // valid value to place into the trie, but for branch nodes bytes(0) can exist
                // even when the value wasn't explicitly placed there. Geth treats a value of
                // bytes(0) as "key does not exist" and so we do the same.
                let value = decoded_node
                    .get(TREE_RADIX)
                    .ok_or(RlpError::Custom("Out of bounds"))?
                    .clone();

                if value.is_empty() {
                    return Err(RlpError::Custom(
                        "value length must be greater than zero (branch)",
                    ));
                } else if i != proof.len() - 1 {
                    return Err(RlpError::Custom(
                        "value node must be last node in proof (branch)",
                    ));
                }

                return Ok(value);
            } else {
                // We're not at the end of the key yet.
                // Figure out what the next node ID should be and continue.
                // uint8 branchKey = uint8(key[currentKeyIndex]);
                // RLPReader.RLPItem memory nextNode = currentNode.decoded[branchKey];
                // currentNodeID = _getNodeID(nextNode);
                // currentKeyIndex += 1;
                let branch_key = *key
                    .get(current_key_index)
                    .ok_or(RlpError::Custom("Out of bounds"))?;
                let next_node = decoded_node
                    .get(branch_key as usize)
                    .ok_or(RlpError::Custom("Out of bounds"))?;
                current_node_id = get_node_id(&next_node)?.into();
                current_key_index += 1;
            }
        } else if decoded_node.len() == LEAF_OR_EXTENSION_NODE_LENGTH {
            let path: Bytes =
                Decodable::decode(&mut decoded_node.first().expect("Impossibly empty").as_ref())?;
            let path_nibbles = to_nibbles(&mut &path);
            let prefix = path_nibbles[0];
            let offset = 2 - (prefix % 2);

            let path_remainder = &path_nibbles[offset as usize..];
            let key_remainder = &key[current_key_index..];
            let shared_nibble_length = shared_nibble_length(&path_remainder, &key_remainder);

            // Whether this is a leaf node or an extension node, the path remainder MUST be a
            // prefix of the key remainder (or be equal to the key remainder) or the proof is
            // considered invalid.
            if path_remainder.len() != shared_nibble_length {
                return Err(RlpError::Custom(
                    "Path remainder must share all nibbles with key",
                ));
            }

            match prefix {
                PREFIX_LEAF_EVEN | PREFIX_LEAF_ODD => {
                    // Prefix of 2 or 3 means this is a leaf node. For the leaf node to be valid,
                    // the key remainder must be exactly equal to the path remainder. We already
                    // did the necessary byte comparison, so it's more efficient here to check that
                    // the key remainder length equals the shared nibble length, which implies
                    // equality with the path remainder (since we already did the same check with
                    // the path remainder and the shared nibble length).
                    if key_remainder.len() != shared_nibble_length {
                        return Err(RlpError::Custom(
                            "key remainder must be identical to path remainder",
                        ));
                    }

                    // Our Merkle Trie is designed specifically for the purposes of the Ethereum
                    // state trie. Empty values are not allowed in the state trie, so we can safely
                    // say that if the value is empty, the key should not exist and the proof is
                    // invalid.
                    let value = decoded_node
                        .get(1)
                        .ok_or(RlpError::Custom("Out of bounds"))?
                        .clone();

                    if value.is_empty() {
                        return Err(RlpError::Custom(
                            "value length must be greater than zero (branch)",
                        ));
                    } else if i != proof.len() - 1 {
                        return Err(RlpError::Custom(
                            "value node must be last node in proof (branch)",
                        ));
                    }

                    return Ok(value);
                }
                PREFIX_EXTENSION_EVEN | PREFIX_EXTENSION_ODD => {
                    // Prefix of 0 or 1 means this is an extension node. We move onto the next node
                    // in the proof and increment the key index by the length of the path remainder
                    // which is equal to the shared nibble length.
                    let node = decoded_node[1].as_ref();
                    current_node_id = get_node_id(&node)?.into();
                    current_key_index += shared_nibble_length;
                }
                _ => return Err(RlpError::Custom("Invalid prefix")),
            }
        }
    }

    Err(RlpError::InputTooShort)
}

pub(crate) fn get_node_id(mut node: &[u8]) -> Result<Vec<u8>, RlpError> {
    if node.len() <= 32 {
        Ok(node.to_vec())
    } else {
        Decodable::decode(&mut node)
    }
}

/// Converts a byte slice into a vector of nibbles.
pub(crate) fn to_nibbles(b: &[u8]) -> Bytes {
    b.iter().flat_map(|byte| [byte >> 4, byte & 0x0f]).collect()
}

/// Determines the number of shared nibbles between two slices. This function short-circuits due
/// to the `take_while` iterator adapter.
pub(crate) fn shared_nibble_length(a: &[u8], b: &[u8]) -> usize {
    a.iter().zip(b.iter()).take_while(|(x, y)| x == y).count()
}

