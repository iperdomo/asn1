(ns asn1.parser-test
  (:require [asn1.parser :refer [length oid base64-buffer tags parse-asn1 sub-oid oid]]
            [clojure.java.io :as io]
            [clojure.pprint :as pp]
            [clojure.string :as str]
            [clojure.test :refer [deftest testing is]])
  (:import [java.nio ByteBuffer]))

(deftest parsing-length
  (testing "Getting length from a ByteBuffer"
    (let [bb-1 (ByteBuffer/wrap (byte-array [0x82 0x02 0x5e]))
          bb-2 (ByteBuffer/wrap (byte-array [0x77 0x02 0x01]))
          bb-3 (ByteBuffer/wrap (byte-array [0x81 0x81 0x00]))]
      (is (= 606 (length bb-1)))
      (is (= 119 (length bb-2)))
      (is (= 129 (length bb-3))))))

(deftest parsing-oid
  (testing "Parsing a byte[] into a OID string"
    (let [rsa-1 (byte-array [0x2a 0x86 0x48 0xce 0x3d 0x03 0x01 0x07])
          rsa-2 (byte-array [0x2a 0x86 0x48 0x86 0xf7 0x0d 0x01 0x01 0x01])]
      (is (= "1.2.840.10045.3.1.7" (oid rsa-1)))
      (is (= "1.2.840.113549.1.1.1" (oid rsa-2))))))

(comment


  (def bb-rsa (base64-buffer (io/file (io/resource "rsa_sample.pem"))))
  (def bb-ec (base64-buffer (io/file (io/resource "ec_private.pem"))))

  (format "%02x" (.get bb-ec 1))      ;; => 0x77
  (Byte/toUnsignedInt (.get bb-ec 1)) ;; => 119


  (format "%02x" (.get bb-rsa 1))      ;; => 0x82
  (Byte/toUnsignedInt (.get bb-rsa 1)) ;; => 130

  ;; if byte[1] > 127
  ;; check byte[2]
  (format "%02x" (.get bb-rsa 2))      ;; => 02
  (format "%02x" (.get bb-rsa 3))      ;; => 5e


  (int (.get bb-rsa 2))
  (Integer/toUnsignedString (Byte/toUnsignedInt (.get bb-rsa 3)) 2)

  (format "%02x" (.get bb-rsa 0))   ;; =>   30

  (Byte/toUnsignedInt (.get bb-rsa 1)) ;; 130
  (Byte/toUnsignedInt (.get bb-rsa 2)) ;; 2
  (Byte/toUnsignedInt (.get bb-rsa 3)) ;; 94

  (= (Byte/toUnsignedInt (.get bb-rsa 1))
     (Integer/parseUnsignedInt "82" 16)
     0x82)

  (tags (Byte/toUnsignedInt (.get bb-rsa 1))) ;; :rsa

  (= (Byte/toUnsignedInt (.get bb-ec 1))
     (Integer/parseUnsignedInt "77" 16)
     0x77)

  (.rewind bb-ec)
  (.limit bb-ec)

  (count (:value (first (parse-asn1 bb-ec))))

  (-> "ec_private.pem"
      io/resource
      io/file
      base64-buffer
      parse-asn1
      pp/pprint)

    (-> "rsa_sample.pem"
      io/resource
      io/file
      base64-buffer
      parse-asn1
      pp/pprint)

    (-> "rsa_private.pem"
        io/resource
        io/file
        base64-buffer
        parse-asn1
        pp/pprint)


    ;; https://docs.microsoft.com/en-us/windows/win32/seccertenroll/about-object-identifier

    0x0137 ;; 311

    (Integer/toBinaryString 0x01)
    (Integer/toBinaryString 0x37)

    0000 0001
    0011 0111

    1000 0010 ;; setting to 1 bit of 1st byte, shift left 1 bit
    0011 0111 ;; set (ignore) bit 7 of 2nd byte

    ;; decoding
    0000 0001
    0011 0111


    ;; 2a 86 48 ce 3d 03 01 07


    0x2a ;; 42
    (quot 42 40) ;; 1
    (rem 42 40) ;; 2

    ;; length 8 (given by the octect lenght)

    0x86 0x48

    2r10000110 ;; 134
    2r01001000 ;; 72

    2r00000011 ;; 3
    2r01001000 ;; 72



    0x0348 ;; 840

    0xce
    0x3d

    (= 0x86 2r10000110 134) ;; true
    2r00000011  ;; 3

    2r01111111

    (Long/toBinaryString (unsigned-bit-shift-right (bit-and 0x7f (Integer/parseUnsignedInt "86" 16)) 1)) ;; 11
    (unsigned-bit-shift-right (bit-and 0x7f (Integer/parseUnsignedInt "86" 16)) 1) ; 3

    (first (byte-array [0x2a]))

    (oid (ByteBuffer/wrap (byte-array [0x2a 0x86 0x48 0xce 0x3d 0x03 0x01 0x07])))


    (sub-oid (ByteBuffer/wrap (byte-array [0x86 0x48]))) ;; 840

    ;;
    (oid (ByteBuffer/wrap (byte-array [0x2a 0x86 0x48 0x86 0xf7 0x0d 0x01 0x01 0x01])))

    0x86 ; 134
    0xf7 ; 247
    0x0d ; 13

    (Long/toBinaryString (bit-and 0x7f 0x86)) ;; 0000110
    (Long/toBinaryString (bit-and 0x7f 0xf7)) ;; 1110111
    (Long/toBinaryString (bit-and 0x7f 0x0d)) ;; 0001101
    (bit-and 0x7f 0x0d) ;; 13 // remains the same

    2r00000011
    2r01111011
    2r00001101

    (Long/parseLong
     (str/join [(.substring (Integer/toBinaryString 0x86) 1)
                (.substring (Integer/toBinaryString 0xf7) 1)
                "000"
                (Integer/toBinaryString 0x0d)]) 2)

    2r000011011101110001101 ;; 113459

    (Long/parseLong
     (str/join [(.substring (Integer/toBinaryString 0x86) 1)
                (Integer/toBinaryString 0x48)]) 2) ;; 840

    2r0000110 1001000

    (.replace (format "%7s" "1101") " " "0")

  (Integer/parseUnsignedInt "02" 16) ;; 2
  (Integer/parseUnsignedInt "5e" 16) ;; 94

  0x025e ;; 606


  0x0a

  (tags (Byte/toUnsignedInt (.get bb-ec))) ;; :sequence
  (tags (Byte/toUnsignedInt (.get bb-ec))) ;; :ec
  (tags (Byte/toUnsignedInt (.get bb-ec))) ;; :integer
  (Byte/toUnsignedInt (.get bb-ec))        ;; 1 (size)
  (Byte/toUnsignedInt (.get bb-ec))        ;; 1 (value)
  (tags (Byte/toUnsignedInt (.get bb-ec))) ;; :octet-string
  (Byte/toUnsignedInt (.get bb-ec))        ;; 32 bytes

  (.position bb-ec) ;; 7

  (let [dst (byte-array 32)]
    (.get bb-ec dst 0 32)
    (map #(format "%02x" %) dst))

  (.position bb-ec) ;; 39

  (Byte/toUnsignedInt (.get bb-ec)) ;; 160 = 0xa0

  (Byte/toUnsignedInt (.get bb-ec)) ;; 10 bytes

  (let [dst (byte-array 10)]
    (.get bb-ec dst 0 10)
    (map #(format "%02x" %) dst)) ;; 0x06 -> object-identifier 0x08 (8) bytes

  (Byte/toUnsignedInt (.get bb-ec)) ;; 161 = 0xa1 = :tag-1
  (Byte/toUnsignedInt (.get bb-ec)) ;; 68 bytes
  (tags (Byte/toUnsignedInt (.get bb-ec))) ;; :bit-string
  (Byte/toUnsignedInt (.get bb-ec)) ;; 66 bytes

  (let [dst (byte-array 66)]
    (.get bb-ec dst 0 66)
    (map #(format "%02x" %) dst))

  (.position bb-ec) ;; 121
  )
