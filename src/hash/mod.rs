pub mod md5;
pub mod sha1;

#[cfg(test)]
mod tests {
    use hex;

    use super::md5::MD5Hash;
    use super::sha1::SHA1Hash;

    const EMPTY_MESSAGE: &str = "";

    const SOME_TEXT: &str = "a-very-long-message-that-cannot-be-digested-at-once";

    const LONG_TEXT: &str = "God? You'd assert that a God exhibits neither shame nor despair. And yet I stand unchanged; \
a tragic husk with bloodied hands. I surrendered my future, the prospect of a family to carry your poison. \
You misled me. I renounce your control!
Fidelity has always been your greatest quality, Ragnier. I swear to you to my son, all of your shame and guilt, \
all of your sins, they will collapse into the abyss we all race towards. Share that truth with the world, share it \
with the provinces and the valley and the empires in the west. Show them your conviction, \
show them the serenity of the void.";

    #[test]
    fn test_md5() {
        assert_eq!(hex::encode(MD5Hash::digest_message(EMPTY_MESSAGE.as_bytes()).to_raw()),
                   "d41d8cd98f00b204e9800998ecf8427e");

        assert_eq!(hex::encode(MD5Hash::digest_message(SOME_TEXT.as_bytes()).to_raw()),
                   "5748be477f8cab2e6d785cd2412b823c");

        assert_eq!(hex::encode(MD5Hash::digest_message(LONG_TEXT.as_bytes()).to_raw()),
                   "406ef8da29b4c6c7e64ff1d163ad7b90");
    }

    #[test]
    fn test_sha1() {
        assert_eq!(hex::encode(SHA1Hash::digest_message(EMPTY_MESSAGE.as_bytes()).to_raw()),
                   "da39a3ee5e6b4b0d3255bfef95601890afd80709");

        assert_eq!(hex::encode(SHA1Hash::digest_message(SOME_TEXT.as_bytes()).to_raw()),
                   "fc0557cb580c6cc1949f126d0020ef6e7eadba7d");

        assert_eq!(hex::encode(SHA1Hash::digest_message(LONG_TEXT.as_bytes()).to_raw()),
                   "6b73c6677532abff53f5ccb966f4dbdb8b1c2185");
    }
}