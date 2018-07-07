#!/usr/bin/python
from splinter import Browser
b = Browser()
url = 'http://google.com'
b.visit(url)
b.click_link_by_text('Sign up')
b.select("rateplanid","spn")
b.fill('spn_postal', '11223')
b.fill('spn_email', '333333@mailinator.com')
b.check('spn_terms')
b.find_by_value('submit').first.click()
b.find_by_value('submit').first.click()
url = 'http://google.com'
