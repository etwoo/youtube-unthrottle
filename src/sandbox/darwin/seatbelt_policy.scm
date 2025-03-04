(version 1)

; deny by default, and require exceptions to opt-in
(deny default)
; deny stragglers that are not covered by (deny default)
(deny process-info*)
(deny nvram*)
(deny iokit-get-properties)
(deny file-map-executable)

(define tmpdir-dynamic (param "TMPDIR"))
(define (require-any-tmpdir extension-id)
  (require-all
    (require-any
      (subpath tmpdir-dynamic)
      (subpath "/private/tmp")
      (subpath "/private/var/tmp")
      (literal "/tmp")
      (literal "/var")
      (literal "/var/tmp"))
    (extension extension-id)))

(allow file-read*
  (require-any-tmpdir "com.apple.app-sandbox.read"))

(allow file-read* file-write*
  (require-any-tmpdir "com.apple.app-sandbox.write"))

(allow network-outbound
  (require-all
    (require-any
      (control-name "com.apple.netsrc")
      (literal "/private/var/run/mDNSResponder")
      (remote tcp))
    (extension "com.apple.security.network.client")))

(allow mach-lookup
  (require-all
    (require-any
      (global-name "com.apple.SecurityServer")
      (global-name "com.apple.networkd")
      (global-name "com.apple.ocspd")
      (global-name "com.apple.trustd.agent")
      (global-name "com.apple.SystemConfiguration.DNSConfiguration")
      (global-name "com.apple.SystemConfiguration.configd"))
    (extension "com.apple.security.network.client")))
