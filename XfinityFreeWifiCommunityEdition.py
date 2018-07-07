#!/usr/bin/python
import random
from splinter import Browser

email    = str(random.randrange(10000000,99999999))+'@comcast.com'
zip_code = random.randrange(10000,99999)
url      = 'http://captive.apple.com'
browser  = Browser('firefox')

browser.visit(url)
browser.click_link_by_text('Sign up')
browser.select("rateplanid","spn")
browser.fill('spn_postal', zip_code)
browser.fill('spn_email', email)
browser.check('spn_terms')
browser.find_by_value('submit').first.click()
browser.find_by_value('submit').first.click()
browser.quit()
