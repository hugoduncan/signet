(ns signet.ring-test
  (:use [signet.ring] :reload-all)
  (:use [clojure.test])
  (:require
   [clj-time.core :as clj-time]
   [clj-time.format :as time-format]))

(defonce public-key "-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0ueqo76MXuP6XqZBILFz
iH/9AI7C6PaN5W0dSvkr9yInyGHSz/IR1+4tqvP2qlfKVKI4CP6BFH251Ft9qMUB
uAsnlAVQ1z0exDtIFFOyQCdR7iXmjBIWMSS4buBwRQXwDK7id1OxtU23qVJv+xwE
V0IzaaSJmaGLIbvRBD+qatfUuQJBMU/04DdJIwvLtZBYdC2219m5dUBQaa4bimL+
YN9EcsDzD9h9UxQo5ReK7b3cNMzJBKJWLzFBcJuePMzAnLFktr/RufX4wpXe6XJx
oVPaHo72GorLkwnQ0HYMTY8rehT4mDi1FI969LHCFFaFHSAaRnwdXaQkJmSfcxzC
YQIDAQAB
-----END PUBLIC KEY-----")

(defonce private-key "-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0ueqo76MXuP6XqZBILFziH/9AI7C6PaN5W0dSvkr9yInyGHS
z/IR1+4tqvP2qlfKVKI4CP6BFH251Ft9qMUBuAsnlAVQ1z0exDtIFFOyQCdR7iXm
jBIWMSS4buBwRQXwDK7id1OxtU23qVJv+xwEV0IzaaSJmaGLIbvRBD+qatfUuQJB
MU/04DdJIwvLtZBYdC2219m5dUBQaa4bimL+YN9EcsDzD9h9UxQo5ReK7b3cNMzJ
BKJWLzFBcJuePMzAnLFktr/RufX4wpXe6XJxoVPaHo72GorLkwnQ0HYMTY8rehT4
mDi1FI969LHCFFaFHSAaRnwdXaQkJmSfcxzCYQIDAQABAoIBAQCW3I4sKN5B9jOe
xq/pkeWBq4OvhW8Ys1yW0zFT8t6nHbB1XrwscQygd8gE9BPqj3e0iIEqtdphbPmj
VHqTYbC0FI6QDClifV7noTwTBjeIOlgZ0NSUN0/WgVzIOxUz2mZ2vBZUovKILPqG
TOi7J7RXMoySMdcXpP1f+PgvYNcnKsT72UcWaSXEV8/zo+Zm/qdGPVWwJonri5Mp
DVm5EQSENBiRyt028rU6ElXORNmoQpVjDVqZ1gipzXkifdjGyENw2rt4V/iKYD7V
5iqXOsvP6Cemf4gbrjunAgDG08S00kiUgvVWcdXW+dlsR2nCvH4DOEe3AYYh/aH8
DxEE7FbtAoGBAPcNO8fJ56mNw0ow4Qg38C+Zss/afhBOCfX4O/SZKv/roRn5+gRM
KRJYSVXNnsjPI1plzqR4OCyOrjAhtuvL4a0DinDzf1+fiztyNohwYsW1vYmqn3ti
EN0GhSgE7ppZjqvLQ3f3LUTxynhA0U+k9wflb4irIlViTUlCsOPkrNJDAoGBANqL
Q+vvuGSsmRLU/Cenjy+Mjj6+QENg51dz34o8JKuVKIPKU8pNnyeLa5fat0qD2MHm
OB9opeQOcw0dStodxr6DB3wi83bpjeU6BWUGITNiWEaZEBrQ0aiqNJJKrrHm8fAZ
9o4l4oHc4hI0kYVYYDuxtKuVJrzZiEapTwoOcYiLAoGBAI/EWbeIHZIj9zOjgjEA
LHvm25HtulLOtyk2jd1njQhlHNk7CW2azIPqcLLH99EwCYi/miNH+pijZ2aHGCXb
/bZrSxM0ADmrZKDxdB6uGCyp+GS2sBxjEyEsfCyvwhJ8b3Q100tqwiNO+d5FCglp
HICx2dgUjuRVUliBwOK93nx1AoGAUI8RhIEjOYkeDAESyhNMBr0LGjnLOosX+/as
qiotYkpjWuFULbibOFp+WMW41vDvD9qrSXir3fstkeIAW5KqVkO6mJnRoT3Knnra
zjiKOITCAZQeiaP8BO5o3pxE9TMqb9VCO3ffnPstIoTaN4syPg7tiGo8k1SklVeH
2S8lzq0CgYAKG2fljIYWQvGH628rp4ZcXS4hWmYohOxsnl1YrszbJ+hzR+IQOhGl
YlkUQYXhy9JixmUUKtH+NXkKX7Lyc8XYw5ETr7JBT3ifs+G7HruDjVG78EJVojbd
8uLA+DdQm5mg4vd1GTiSK65q/3EeoBlUaVor3HhLFki+i9qpT8CBsg==
-----END RSA PRIVATE KEY-----")

(deftest pem-decode-test
  (is (instance? java.security.spec.RSAPrivateCrtKeySpec
                 (pem-decode (.getBytes private-key))))
  (is (instance? java.security.spec.X509EncodedKeySpec
                 (pem-decode (.getBytes public-key)))))

(deftest pem-encode-test
  (testing "roundtrip"
    ; pkcs#1 -> key -> pkcs#8, so not testable
    (is (= public-key
           (pem-encode
            (rsa-public-key (pem-decode (.getBytes public-key)))))))
  (testing "roundtrip to key"
    (is (= (rsa-key (pem-decode (.getBytes private-key)))
           (rsa-key
            (pem-decode
             (.getBytes
              (pem-encode
               (rsa-key (pem-decode (.getBytes private-key)))))))))
    (is (= (rsa-public-key (pem-decode (.getBytes public-key)))
           (rsa-public-key
            (pem-decode
             (.getBytes
              (pem-encode
               (rsa-public-key (pem-decode (.getBytes public-key)))))))))))

(deftest canonical-path-test
  (is (= "/" (canonical-path "///")) "elide multiple /")
  (is (= "/path" (canonical-path "/path/")) "Remove trailing /")
  (is (= "/" (canonical-path "/")) "Leave single /"))

(deftest digest-path-test
  (is (= "YtBWDn1blGGuFIuKksdwXzHU9oE="
         (digest-path "/organizations/clownco"))))

(deftest digest-body-test
  (is (= "DFteJZPVv6WKdQmMqZUQUumUyRs="
         (digest-body "Spec Body"))))

(deftest sign-test
  (let [key (rsa-key (pem-decode (.getBytes private-key)))]
    (is (= "KhJGw4UnPhAzIaVfQaS1MpZBgPqnywziGBijUxs7C/o8tAugUcFuVpryD87cYwT27n99ZEJVC+KDZBg5uV9S4ST3ZgWmlGQRFiN/A+Irl8qN/uLV4JGgsgmEAFOdwuS6JFI6RM1UMyezeEhKR9I0XZcl2kYbOw9R2uqgYceeSCgRUHEaOk2S4uB+RQeLYs4eyXHrKvM8jk4l1xM75oq3ejN3MA962Ura+BJUoj/IkfJjgdSbem3LFG5NbCXFDG7cLZ7W2FKUkiLt8YPm1Z4mkUdIWOkFN2RIO6QogOdLWrcvYAT6r2FBqS5wYixT3NbFHfw2lMprXTLSjH1Q2MM10A=="
           (sign (.getBytes "/organizations/clownco") key)))))


(deftest valid-timestamp?-test
  (let [now (clj-time/now)
        ts (fn [t] (time-format/unparse time-formatter t))
        t+ (fn [t s] (clj-time/plus t (clj-time/secs s)))]
    (testing "valid timestamps"
      (is (valid-timestamp? (ts now) 0 now))
      (is (valid-timestamp? (ts now) 100 (t+ now -99)))
      (is (valid-timestamp? (ts now) 100 (t+ now 99))))
    (testing "invalid timestamps"
      (is (not (valid-timestamp? (ts (t+ now 2)) 1 now)))
      (is (not (valid-timestamp? (ts (t+ now -2)) 1 now))))
    (testing "zero max-skew as disabling test"
      (is (valid-timestamp? (ts (t+ now 1)) 0 now)))))

(def auth-lines
     ["jVHrNniWzpbez/eGWjFnO6lINRIuKOg40ZTIQudcFe47Z9e/HvrszfVXlKG4"
      "NMzYZgyooSvU85qkIUmKuCqgG2AIlvYa2Q/2ctrMhoaHhLOCWWoqYNMaEqPc"
      "3tKHE+CfvP+WuPdWk4jv4wpIkAz6ZLxToxcGhXmZbXpk56YTmqgBW2cbbw4O"
      "IWPZDHSiPcw//AYNgW1CCDptt+UFuaFYbtqZegcBd2n/jzcWODA7zL4KWEUy"
      "9q4rlh/+1tBReg60QdsmDRsw/cdO1GZrKtuCwbuD4+nbRdVBKv72rqHX9cu0"
      "utju9jzczCyB+sSAQWrxSsXB/b8vV2qs0l4VD2ML+w=="])

(deftest seal-test
  (let [user-id "spec-user"
        body "Spec Body"
        path "/organizations/clownco"
        timestamp "2009-01-01T12:00:00Z"
        key (rsa-key (pem-decode (.getBytes private-key)))
        sealed (seal {:uri path :body body :request-method :POST}
                     user-id key timestamp)]
    (is (= (reduce
            #(do
               (is (= (first %2)
                      (get %1 (format "X-Ops-Authorization-%s" (second %2)))))
               %1)
            (:headers sealed)
            (map vector auth-lines (iterate inc 1)))))
    (is (= timestamp (-> sealed :headers (get x-ops-timestamp))))
    (is (= user-id (-> sealed :headers (get x-ops-userid))))))

(deftest verify-test
  (testing "valid seal"
    (let  [user-id "spec-user"
           body "Spec Body"
           path "/organizations/clownco"
           key (rsa-key (pem-decode (.getBytes private-key)))
           pkey (rsa-public-key (pem-decode (.getBytes public-key)))]
      (is
       (verify
        (seal {:uri path :body body :request-method :POST} user-id key)
        pkey))))
  (testing "invalid timestamp"
    (let  [user-id "spec-user"
           body "Spec Body"
           path "/organizations/clownco"
           timestamp "2009-01-01T12:00:00Z"
           key (rsa-key (pem-decode (.getBytes private-key)))
           pkey (rsa-public-key (pem-decode (.getBytes public-key)))]
      (is
       (not
        (verify
         (seal
          {:uri path :body body :request-method :POST} user-id key timestamp)
         pkey)))))
  (testing "invalid path"
    (let  [user-id "spec-user"
           body "Spec Body"
           path "/organizations/clownco"
           key (rsa-key (pem-decode (.getBytes private-key)))
           pkey (rsa-public-key (pem-decode (.getBytes public-key)))]
      (is
       (not
        (verify
         (assoc
             (seal
              {:uri path :body body :request-method :POST} user-id key)
           :uri (str path "_"))
         pkey))))))
