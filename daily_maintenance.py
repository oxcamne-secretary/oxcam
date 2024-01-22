#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
this is spawned in it's own thread by the email daemon when local time passes midnight

It can also be run in development using a launch.json configuration:

        {
            "name": "Python: daily",
            "type": "python",
            "request": "launch",
            "program": "py4web.py",
            "args": [
                "call", "apps", "oxcam.daily_maintenance.daily_maintenance"
            ],
            "console": "integratedTerminal",
            "justMyCode": false
        },
 
"""
import datetime
import os
from pathlib import Path
from .common import db, auth, logger
from .settings import SOCIETY_SHORT_NAME, STRIPE_SKEY, IS_PRODUCTION, ALLOWED_EMAILS, \
	SUPPORT_EMAIL, LETTERHEAD, SOCIETY_NAME, DB_URL, DATE_FORMAT
from .utilities import member_greeting
from .stripe_interface import stripe_subscription_cancelled
from .models import primary_email
from yatl.helpers import HTML, XML

def daily_maintenance():
	os.chdir(Path(__file__).resolve().parent.parent.parent) #working directory py4web
	#keep only most recent month's backup plus monthly (month day 1) backups for one year
	items = os.listdir(".")
	dname = datetime.date.today().strftime("%d") + '.csv'
	yname = (datetime.date.today()-datetime.timedelta(days=365)).strftime("%Y%m01") + '.csv'
	for i in items:
		if (i.endswith(dname) and (datetime.date.today().day != 1)) or i.endswith(yname):
			os.remove(i)

	#send renewal reminders at 9 day intervals from one interval before to two intervals after renewal date
	#note that full memberships will generally be auto renewing Stripe subscriptions, but legacy memberships and
	#student memberships still need manual renewal.
	interval = 9
	first_date = datetime.date.today() - datetime.timedelta(days=interval*2)
	last_date = datetime.date.today() + datetime.timedelta(days=interval)

	members = db((db.Members.Paiddate>=first_date)&(db.Members.Paiddate<=last_date)&(db.Members.Membership!=None)&\
				(db.Members.Pay_subs==None)&(db.Members.Charged==None)).select()
	for m in members:
		if (m.Paiddate - datetime.date.today()).days % interval == 0:
			text = f"{LETTERHEAD.replace('&lt;subject&gt;', 'Renewal Reminder')}{member_greeting(m)}"
			text += f"<p>This is a friendly reminder that your {SOCIETY_NAME} membership expiration \
date is/was {m.Paiddate.strftime(DATE_FORMAT)}. Please renew by <a href={DB_URL}> logging in</a> \
and selecting join/renew from the menu of choices, \
or cancel membership to receive no futher reminders.</p><p>\
We are very grateful for your membership support and hope that you will renew!</p>\
If you have any questions, please contact {SUPPORT_EMAIL}"
			if IS_PRODUCTION:
				auth.sender.send(to=primary_email(m.id), reply_to=SUPPORT_EMAIL, sender=SUPPORT_EMAIL, subject='Renewal Reminder', body=HTML(XML(text)))
			logger.info(f"Renewal Reminder sent to {primary_email(m.id)}")

	subs = db((db.Members.Pay_subs!=None)&(db.Members.Pay_subs!='Cancelled')).select()
	for m in subs:
		if eval(f"{m.Pay_source}_subscription_cancelled(m)"):	#subscription no longer operational
			if IS_PRODUCTION:
				text = f"{LETTERHEAD.replace('&lt;subject&gt;', 'Membership Renewal Failure')}{member_greeting(m)}"
				text += f"<p>We have been unable to process your auto-renewal and as a result your membership has been cancelled. </p><p>\
We hope you will <a href={DB_URL}> reinstate your membership</a>, \
but in any case we are grateful for your past support!</p>\
If you have any questions, please contact {SUPPORT_EMAIL}"
				auth.sender.send(to=primary_email(m.id), reply_to=SUPPORT_EMAIL, sender=SUPPORT_EMAIL, subject='Membership Renewal Failure', body=HTML(XML(text)))
			logger.info(f"Membership Subscription Cancelled {primary_email(m.id)}")
			m.update_record(Pay_subs = 'Cancelled', Pay_next=None, Modified=datetime.datetime.now())

	file=open(f'{SOCIETY_SHORT_NAME}_backup_{datetime.date.today().strftime("%Y%m%d")}.csv',
					'w', encoding='utf-8', newline='')
	db.export_to_csv_file(file)
				
	db.commit()
