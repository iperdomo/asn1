;; This Source Code Form is subject to the terms of
;; the Mozilla Public License, v. 2.0. If a copy of the
;; MPL was not distributed with this file, You can
;; obtain one at https://mozilla.org/MPL/2.0/.

(ns asn1.parser
  (:require [clojure.java.io :as io]
            [clojure.pprint  :refer [pprint]]
            [clojure.string  :as str])
  (:import java.nio.ByteBuffer
           java.util.Base64))

;; https://tools.ietf.org/html/rfc5915
;;
;; ECPrivateKey ::= SEQUENCE {
;;     version        INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
;;     privateKey     OCTET STRING,
;;     parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
;;     publicKey  [1] BIT STRING OPTIONAL
;; }


;; https://tools.ietf.org/html/rfc2313#section-7.2
;;
;; RSAPrivateKey ::= SEQUENCE {
;;      version Version,
;;      modulus INTEGER, -- n
;;      publicExponent INTEGER, -- e
;;      privateExponent INTEGER, -- d
;;      prime1 INTEGER, -- p
;;      prime2 INTEGER, -- q
;;      exponent1 INTEGER, -- d mod (p-1)
;;      exponent2 INTEGER, -- d mod (q-1)
;;      coefficient INTEGER -- (inverse of q) mod p
;; }
;;
;; Version ::= INTEGER

(def tags {0x02 :integer
           0x03 :bit-string
           0x04 :octet-string
           0x05 :null
           0x06 :object-identifier
           0x10 :sequence
           0x11 :set
           0x13 :printable-string
           0x14 :t61string
           0x16 :ia5string
           0x17 :utctime
           0x30 :sequence
           0xa0 :cont-0
           0xa1 :cont-1})

(defn base64-extract
  [path]
  (with-open [r (io/reader path)]
    (reduce str "" (remove #(str/starts-with? % "----") (line-seq r)))))

(defn base64-bytes
  [path]
  (let [b64-str ^String (base64-extract path)]
    (.decode (Base64/getDecoder) b64-str)))

(defn base64-buffer
  [path]
  (ByteBuffer/wrap (base64-bytes path)))

(defn unsigned-int
  [b]
  (Byte/toUnsignedInt b))

(defn get-unsigned
  [^ByteBuffer bb]
  (Byte/toUnsignedInt (.get bb)))

(defmulti parse-tag
  (fn [tag ^ByteBuffer _]
    tag))

(defn parse
  [^ByteBuffer bb limit]
  (loop [parsed []
         remaining? (.hasRemaining bb)
         pos (.position bb)]
    (if (or (= pos limit)
            (not remaining?))
      parsed
      (let [tag (tags (get-unsigned bb))
            current (parse-tag tag bb)]
        (recur (conj parsed current)
               (.hasRemaining bb)
               (.position bb))))))
(defn to-hex
  [b]
  (format "%02x" b))

(defn to-hex-str
  [ba]
  (str/join (map to-hex ba)))

(defn length
  "There are two forms: short (for lengths between 0 and 127), and
  long definite (for lengths between 0 and 2^1008 -1).

  Short form: One octet. Bit 8 has value `0` and bits 7-1 give the
  length.

  Long form: Two to 127 octets. Bit 8 of first octet has value `1` and
  bits 7-1 give the number of additional length octets. Second and
  following octets give the length, base 256, most significant digit
  first."
  [^ByteBuffer bb]
  (let [len (get-unsigned bb)]
    (if (<= len 127)
      len
      (let [bs (Integer/toBinaryString len)
            size (Integer/parseUnsignedInt (.substring bs 1) 2)
            ba (byte-array size)]
        (.get bb ba 0 size)
        (Integer/parseUnsignedInt (to-hex-str ba) 16)))))

(defmethod parse-tag :sequence
  [tag ^ByteBuffer bb]
  (let [len (length bb)
        limit (+ len (.position bb))]
    [tag len (parse bb limit)]))

(defmethod parse-tag :integer
  [tag ^ByteBuffer bb]
  (let [len (length bb)
        value (if (= 1 len)
                (get-unsigned bb)
                (let [ba (byte-array len)]
                  (.get bb ba 0 len)
                  (BigInteger. ba)))]
    [tag len value]))


(defmethod parse-tag :octet-string
  [tag ^ByteBuffer bb]
  (let [len (length bb)
        ba (byte-array len)]
    (.get bb ba 0 len)
    [tag len (to-hex-str ba)]))

(defmethod parse-tag :cont-0
  [tag ^ByteBuffer bb]
  (let [len (length bb)
        limit (+ len (.position bb))]
    [tag len (parse bb limit)]))

(defmethod parse-tag :cont-1
  [tag ^ByteBuffer bb]
  (let [len (length bb)
        limit (+ len (.position bb))]
    [tag len (parse bb limit)]))

;; First attempt
;; Only works for 2 bytes
;; (let [first-byte (unsigned-bit-shift-right (bit-and 0x7F component) 1)
;;             second-byte (get-unsigned bb)
;;             pos (.position bb)
;;   (Long/parseUnsignedLong (str (to-hex first-byte) (to-hex second-byte)) 16))


;; Attribution:
;; https://crypto.stackexchange.com/questions/29115/how-is-oid-2a-86-48-86-f7-0d-parsed-as-1-2-840-113549/29116#29116

(defn left-pad
  [^String s]
  (.replace (format "%8s" s) " " "0"))

(defn to-binary-string
  [b]
  (left-pad (Long/toBinaryString b)))

(defn split-oid-components
  [ba]
  (let [rf (fn
             [m val]
             (let [b (Byte/toUnsignedLong val)]
               (if (<= b 0x7f)
                 (if (:cache m)
                   (-> m
                       (update :result conj (conj (:cache m) b))
                       (dissoc :cache))
                   (update m :result conj b))
                 (if (:cache m)
                   (update m :cache conj b)
                   (assoc m :cache [b])))))]
    (:result (reduce rf {:result []} ba))))


(defn multi-byte-component
  [ba]
  (let [in-bits (map to-binary-string ba)
        take-7 (map #(.substring ^String % 1) in-bits)
        combined (str/join take-7)]
    (Long/parseLong combined 2)))

(defn sub-oid
  [components]
  (loop [components components
         result []]
    (if (empty? components)
      result
      (let [c (first components)
            b (if (coll? c)
                (multi-byte-component c)
                (unsigned-int c))]
        (recur (next components)
               (conj result b))))))

(defn oid
  [ba]
  (let [components (split-oid-components ba)
        first-component (Byte/toUnsignedInt (first components))
        result [(quot first-component 40) (rem first-component 40)]
        components (next components)
        result (apply concat [result (sub-oid components)])]
    (str/join "." result)))

(defmethod parse-tag :object-identifier
  [tag ^ByteBuffer bb]
  (let [len (length bb)
        ba (byte-array len)]
    (.get bb ba 0 len)
    [tag len (oid ba)]))

(defn to-bit-string
  [ba]
  (str/join (map to-binary-string ba)))

(defmethod parse-tag :bit-string
  [tag ^ByteBuffer bb]
  (let [len (length bb)
        ba (byte-array len)]
    (.get bb ba 0 len)
    [tag len (to-bit-string ba)]))

(defmethod parse-tag :null
  [tag ^ByteBuffer bb]
  (let [len (length bb)]
    [tag len nil]))

(defmethod parse-tag :default
  [_ ^ByteBuffer bb]
  (let [len (length bb)
        ba (byte-array len)]
    (.get bb ba 0 len)
    [:unknown len (to-hex-str ba)]))

(defn parse-asn1
  [^ByteBuffer bb]
  (.rewind bb)
  (parse bb (.limit bb)))

(defn -main [& args]
  (if-let [key-path (first args)]
    (pprint (parse-asn1 (base64-buffer key-path)))
    (binding [*out* *err*]
      (println "no path given")
      (System/exit 1))))
