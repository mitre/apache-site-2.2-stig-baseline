APACHE_HOME= attribute(
  'apache_home',
  description: 'location of apache home directory',
  default: '/etc/httpd'
)

APACHE_CONF_DIR= attribute(
  'apache_conf_dir',
  description: 'location of apache conf directory',
  default: '/etc/httpd/conf'
)

APACHE_LOG_DIR= attribute(
  'apache_log_dir',
  description: 'location of apache log directory',
  default: '/etc/httpd/logs'
)

control "V-26279" do
  title "Error logging must be enabled."
  desc  "The server error logs are invaluable because they can also be used to
identify potential problems and enable proactive remediation.  . Log data can
reveal anomalous behavior such as “not found” or “unauthorized” errors that may
be an evidence of attack attempts.   Failure to enable error logging can
significantly reduce the ability of Web Administrators to detect or remediate
problems. "
  impact 0.5
  tag "gtitle": "WA00605"
  tag "gid": "V-26279"
  tag "rid": "SV-33192r1_rule"
  tag "stig_id": "WA00605 A22"
  tag "fix_id": "F-29376r1_fix"
  tag "cci": []
  tag "nist": ["Rev_4"]
  tag "documentable": false
  tag "responsibility": "Web Administrator"
  tag "ia_controls": "ECAR-1"
  tag "check": "Enter the following command:

grep \"ErrorLog\" /usr/local/apache2/conf/httpd.conf

This directive lists the name and location of the error log.

If the command result lists no data, this is a finding.
"
  tag "fix": "Edit the httpd.conf file and enter the name and path to the
ErrorLog."

  describe apache_conf("#{APACHE_CONF_DIR}/httpd.conf") do
    its('ErrorLog') { should_not be_nil }
  end
end
