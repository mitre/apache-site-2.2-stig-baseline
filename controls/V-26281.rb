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

control "V-26281" do
  title "System logging must be enabled."
  desc  "The server error logs are invaluable because they can also be used to
identify potential problems and enable proactive remediation. Log data can
reveal anomalous behavior such as “not found” or “unauthorized” errors that may
be an evidence of attack attempts.   Failure to enable error logging can
significantly reduce the ability of Web Administrators to detect or remediate
problems. The CustomLog directive specifies the log file, syslog facility, or
piped logging utility."
  impact 0.5
  tag "gtitle": "WA00615"
  tag "gid": "V-26281"
  tag "rid": "SV-33206r1_rule"
  tag "stig_id": "WA00615 A22"
  tag "fix_id": "F-29381r1_fix"
  tag "cci": []
  tag "nist": ["Rev_4"]
  tag "documentable": false
  tag "responsibility": "Web Administrator"
  tag "ia_controls": "ECAR-1"
  tag "check": "Enter the following command:

grep \"CustomLog\" /usr/local/apache2/conf/httpd.conf

The command should return the following value:.

CustomLog \"Logs/access_log\" common

If the above value is not returned, this is a finding.
"
  tag "fix": "Edit the httpd.conf file and enter the name, path and level for
the CustomLog."

  describe apache_conf("#{APACHE_CONF_DIR}/httpd.conf").CustomLog.map{ |element| element.gsub(/"/, '') }[0] do
    it { should cmp 'Logs/access_log'}
  end
end
