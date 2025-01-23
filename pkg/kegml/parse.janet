#!/usr/bin/env janet

(defn extract-title [filepath]
  (def content (file/read filepath))
  (def match (re-find #"(?m)^# (.+)" content))
  (if match
    (print "Title:" (match 1))
    (print "Title not found")))

(def args (dyn :args))

(if (>= (length args) 1)
  (extract-title (first args))
  (print "Usage: janet script.janet <file-path>"))
