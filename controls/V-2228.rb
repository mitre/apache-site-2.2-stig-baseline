APACHE_HOME= attribute(
  'apache_home',
  description: 'location of apache home directory',
  default: '/etc/httpd'
)

APACHE_CONF_DIR= attribute(
  'apache_home',
  description: 'location of apache conf directory',
  default: '/etc/httpd/conf'
)

control "V-2228" do
  title "All interactive programs (CGI) must be placed in a designated
directory with appropriate permissions."
  desc  "CGI scripts represents one of the most common and exploitable means of
compromising a web server. By definition, CGI are executable by the operating
system of the host server. While access control is provided via the web
service, the execution of CGI programs is not otherwise limited unless the SA
or Web Manager takes specific measures. CGI programs can access and alter data
files, launch other programs and use the network. CGI programs can be written
in any available programming language. C, PERL, PHP, Javascript, VBScript and
shell (sh, ksh, bash) are popular choices."
  impact 0.5
  tag "gtitle": "WG400"
  tag "gid": "V-2228"
  tag "rid": "SV-6928r1_rule"
  tag "stig_id": "WG400 A22"
  tag "fix_id": "F-2277r1_fix"
  tag "cci": []
  tag "nist": ["Rev_4"]
  tag "documentable": false
  tag "responsibility": "System Administrator"
  tag "ia_controls": "DCPA-1"
  tag "check": "To preclude access to the servers root directory, ensure the
following directive is in the httpd.conf file. This entry will also stop users
from setting up .htaccess files which can override security features configured
in httpd.conf.

<DIRECTORY /[website root dir]>
AllowOverride None
</DIRECTORY>

If the AllowOverride None is not set, this is a finding.
"
  tag "fix": "Ensure the CGI (or equivalent i.e. scripts) directory has access
controls IAW the WEB Services STIG."

begin
  doc_root = apache_conf("#{APACHE_CONF_DIR}/httpd.conf").DocumentRoot.map!{ |element| element.gsub(/"/, '') }[0] + '>'
  web_root_idx = apache_conf("#{APACHE_CONF_DIR}/httpd.conf").params['<Directory'].map!{ |element| element.gsub(/"/, '') }.index("#{doc_root}")
  allow_override = apache_conf("#{APACHE_CONF_DIR}/httpd.conf").params['AllowOverride'][web_root_idx]

  describe allow_override do
    it { should cmp 'None' }
  end
end
end
