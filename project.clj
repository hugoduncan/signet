(defproject signet "0.1.0-SNAPSHOT"
  :description "HTTP request signing"
  :dependencies [[org.clojure/clojure "1.2.0-RC3"]
                 [org.clojure/clojure-contrib "1.2.0-RC3"]
                 [net.iharder/base64 "2.3.8"]
                 [net.oauth.core/oauth "20100527"]
                 [clj-time "0.1.0-SNAPSHOT"]]
  :repositories {"build.clojure.org" "http://build.clojure.org/releases/"
                 "clojars.org" "http://clojars.org/repo/"
                 "oauth" "http://oauth.googlecode.com/svn/code/maven"}
  :dev-dependencies [[swank-clojure "1.2.1"]])
