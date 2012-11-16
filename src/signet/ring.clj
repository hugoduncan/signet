(ns signet.ring
  "Signing of HTTP request maps.
  Based on Mixlib::Authentication."
  (:require
    [clojure.string :as string]
    [slingshot.slingshot :as slingshot]
    [clojure.tools.logging :as logging]
    [clj-time.core :as clj-time]
    [clj-time.format :as time-format])
  (:import
    java.security.KeyFactory
    java.security.KeyPairGenerator
    java.security.MessageDigest
    java.security.NoSuchAlgorithmException
    java.security.SecureRandom
    java.security.cert.CertificateFactory
    java.security.cert.X509Certificate
    java.security.spec.PKCS8EncodedKeySpec
    java.security.spec.RSAPrivateKeySpec
    java.security.spec.X509EncodedKeySpec
    javax.crypto.Cipher
    javax.crypto.NoSuchPaddingException
    net.iharder.Base64
    net.oauth.signature.pem.PEMReader
    net.oauth.signature.pem.PKCS1EncodedKeySpec))

(defonce x-ops-authorization- "X-Ops-Authorization-")
(defonce x-ops-content-hash "X-Ops-Content-Hash")
(defonce x-ops-userid "X-Ops-UserId")
(defonce x-ops-sign "X-Ops-Sign")
(defonce x-ops-timestamp "X-Ops-Timestamp")
(defonce sign-version "version=1.0")
(defonce signature-method "Method")
(defonce signature-hashed-path "Hashed Path")

(def ^:dynamic *digest-alg* "sha1")
(def ^:dynamic *cipher-alg* "RSA")

(def markers
     {"-----BEGIN RSA PRIVATE KEY-----" :pkcs#1-private
      "-----BEGIN PRIVATE KEY-----" :pkcs#8
      "-----BEGIN CERTIFICATE-----" :x.509-certificate
      "-----BEGIN PUBLIC KEY-----" :x.509
      "-----BEGIN RSA PUBLIC KEY-----" :pkcs#1-public})

(def begin-markers
  (into {} (map #(vector (second %) (first %)) markers)))

(def end-markers
  (into {} (map #(vector (first %) (string/replace (second %) "BEGIN" "END"))
                begin-markers)))

(defonce cert-factory (delay (CertificateFactory/getInstance "X.509")))
(defonce rsa-key-factory (delay (KeyFactory/getInstance "RSA")))
(defonce rsa-keypair-generator (delay
                                (doto (KeyPairGenerator/getInstance "RSA")
                                  (.initialize 2048 (SecureRandom.)))))

(defn rsa-keypair
  "Return a public, private keypair"
  []
  ((juxt #(.getPublic %) #(.getPrivate %))
   (.generateKeyPair @rsa-keypair-generator)))

(defn pem-encode
  ([key] (pem-encode key (keyword (string/lower-case (.getFormat key)))))
  ([key key-type]
     (str
      (begin-markers key-type)
      \newline
      (string/join
       "\n"
       (map
        #(apply str %)
        (partition
         64 64 (repeat nil)
         (Base64/encodeBytes
          (.getEncoded key)))))
      \newline
      (end-markers key-type))))

(defn pem-decode [bytes]
  "Decode a PEM encoded key/certificate"
  (with-open [in (java.io.ByteArrayInputStream. bytes)]
    (let [reader (PEMReader. in)
          marker (.getBeginMarker reader)]
      (condp = (markers marker)
          :pkcs#1-private (.getKeySpec
                           (PKCS1EncodedKeySpec. (.getDerBytes reader)))
          :pkcs#1-public (.getKeySpec
                          (PKCS1EncodedKeySpec. (.getDerBytes reader)))
          :x.509 (X509EncodedKeySpec. (.getDerBytes reader))
          :x.509-certificate (with-open [in (java.io.ByteArrayInputStream.
                                             (.getDerBytes reader))]
                               (.generateCertificate @cert-factory in))
          :pkcs#8 (PKCS8EncodedKeySpec. (.getDerBytes reader))
          (slingshot/throw+
           :type :unknown-key-encoding
           :message (format
                     "Unknown key encoding for PEM marker %s" marker))))))

(defn rsa-key [keyspec]
  (.generatePrivate @rsa-key-factory keyspec))

(defn rsa-public-key [keyspec]
  (.generatePublic @rsa-key-factory keyspec))

(defn canonical-path
  [path]
  (let [path (string/replace path #"/+" "/")]
    (if (and (> (count path) 1) (.endsWith path "/") )
      (subs path 0 (dec (count path)))
      path)))

(defn digest [bytes]
  (.digest
   (doto (MessageDigest/getInstance *digest-alg*)
     (.update (.getBytes bytes)))))

(defn encrypt [bytes key]
  (.doFinal
   (doto (Cipher/getInstance *cipher-alg*)
     (.init Cipher/ENCRYPT_MODE key))
   bytes))

(defn decrypt [bytes key]
  (.doFinal
   (doto (Cipher/getInstance *cipher-alg*)
     (.init Cipher/DECRYPT_MODE key))
   bytes))

(defn digest-body
  [body]
  (Base64/encodeBytes (digest (or body ""))))

(defn digest-path
  [path]
  (Base64/encodeBytes (digest path)))

(defn sign
  [bytes key]
  (Base64/encodeBytes (encrypt bytes key)))

(defn signature
  "Calculate a signature string for a request"
  [request-method path-hash content-hash timestamp user-id]
  (str
   signature-method ":" (string/upper-case
                         (name (or request-method "GET"))) \newline
   signature-hashed-path ":" path-hash \newline
   x-ops-content-hash ":" content-hash \newline
   x-ops-timestamp ":" timestamp \newline
   x-ops-userid ":" user-id))

(def time-formatter (time-format/formatters :date-time-no-ms))

(defn valid-timestamp?
  ([timestamp-string max-skew]
     (valid-timestamp? timestamp-string max-skew (clj-time/now)))
  ([timestamp-string max-skew now]
     (or
      (zero? max-skew)
      (clj-time/within?
       (clj-time/interval
        (clj-time/minus now (clj-time/secs max-skew))
        (clj-time/plus now (clj-time/secs max-skew)))
       (time-format/parse time-formatter timestamp-string)))))

(defn seal
  "Seal a request, adding appropriate headers for the signature and other
   information."
  ([request user-id key]
     (seal
      request user-id key (time-format/unparse time-formatter (clj-time/now))))
  ([request user-id key timestamp]
  (let [content-hash (digest-body (:body request))
        path-hash (digest-path (:uri request))]
    (reduce
     #(assoc-in
       %1 [:headers (str x-ops-authorization- (second %2))]
       (first %2))
     (->
      request
      (assoc-in [:headers x-ops-content-hash] content-hash)
      (assoc-in [:headers x-ops-userid] user-id)
      (assoc-in [:headers x-ops-sign] sign-version)
      (update-in [:headers x-ops-timestamp]
                 (fn [t]
                   (or t timestamp))))
     (map vector
          (map
           #(apply str %)
           (partition
            60 60 (repeat nil)
            (sign
             (.getBytes
              (signature
               (:request-method request)
               path-hash
               content-hash
               timestamp
               user-id))
             key)))
          (iterate inc 1))))))

(defn auth-headers
  "Extract the sequence of X-Ops-Authorization-. header values."
  ([headers] (auth-headers headers 1))
  ([headers n]
     (lazy-seq
      (if-let [hdr (headers (str x-ops-authorization- n))]
        (cons hdr (auth-headers headers (inc n)))))))


(defn verify
  "Given a request, ensure the signing string matches the request.  This does
   not check the content against the content-hash."
  ([request key] (verify request key (* 15 60)))
  ([request key max-time-skew]
     (let [decrypted (String.
                      (decrypt
                       (Base64/decode
                        (string/join "" (auth-headers (:headers request))))
                       key))
           expected (signature
                     (:request-method request)
                     (Base64/encodeBytes (digest (:uri request)))
                     (-> request :headers (get x-ops-content-hash))
                     (-> request :headers (get x-ops-timestamp))
                     (-> request :headers (get x-ops-userid)))
           matched (= decrypted expected)]
       (logging/debug (format "Decrypted Signature: %s" decrypted))
       (logging/debug (format " Expected Signature: %s" expected))
       (logging/debug (format "Matching Signatures: %s" matched))
       (and matched
            (valid-timestamp?
             (-> request :headers (get x-ops-timestamp))
             max-time-skew)))))
