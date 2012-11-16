(defproject signet "0.1.0-SNAPSHOT"
            :description "HTTP request signing"
            :url "http://github.com/hugoduncan/signet"
            :license {:name "Eclipse Public License - v 1.0"
                      :url "http://www.eclipse.org/legal/epl-v10.html"
                      :distribution :repo
                      :comments "same as Clojure"}
            :dependencies [[org.clojure/clojure "1.4.0"]
                           [org.clojure/tools.logging "0.2.3"]
                           [slingshot "0.10.3"]
                           [net.iharder/base64 "2.3.8"]
                           [net.oauth.core/oauth "20100527"]
                           [clj-time "0.4.4"]])
