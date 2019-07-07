#coding: utf-8
#!/usr/bin/python3.7
#virustotal unofficial bot

from telegram.ext import Updater, CommandHandler, MessageHandler, Filters
from telegram import InlineKeyboardButton, InlineKeyboardMarkup, File
from telegram.error import NetworkError, Unauthorized, BadRequest
import requests
import json
import os
import sys
import requests
import logging

#BOT_TOKEN
API_TOKEN = os.getenv('TOKEN')

#Virus Total api key
VIRUS_TOTAL_APIKEY = os.getenv('VIRUS_TOTAL_API')

#MODE = DEV / PROD
mode = os.getenv('MODE')

logging.basicConfig(level=logging.INFO)

if mode == 'dev':
	def run(updater):
		updater.start_polling()
		updater.idle()

elif mode == 'prod':
	def run(updater):
		PORT = int(os.environ.get('PORT', '8443'))
		HEROKU_APP_NAME = os.environ.get('HEROKU_APP_NAME')

		updater.start_webhook(listen='0.0.0.0',
			port=PORT,
			url_path=API_TOKEN)
		updater.bot.set_webhook('https://{}.herokuapp.com/{}'.format(HEROKU_APP_NAME, API_TOKEN))
else:
	logging.error('MODE NOT FOUND')
	sys.exit()

def get_help(bot, update):
	#show help/commands
	help_text = '''
/help - Show this message
/hash <b>HASH</b> - Analyze a hash (MD5, SHA-1, SHA-256)
/url <b>URL</b> - Analyze a URL
'''

	bot.send_message(parse_mode='HTML', chat_id=update.message.chat_id, text=help_text, reply_to_message_id=update.message.message_id)

def download_file(file_path, file_name):
	with open(file_name, 'wb') as file:
		r = requests.get(file_path)
		file.write(r.content)

		return file

#@run_async
def hash_scan(_hash):
	try:
		#analyze a hash
		url = 'https://www.virustotal.com/vtapi/v2/file/report'
		params = {'apikey':VIRUS_TOTAL_APIKEY,
				'resource':_hash}

		r = requests.get(url, params=params)

		hash_js = json.dumps(r.json())
		hash_js = json.loads(hash_js)

		if hash_js['verbose_msg'] == 'Your resource is queued for analysis':
			new_message = '''
<b>Message: </b>{verbose_msg}
<b>MD5: </b>{md5}
'''.format(verbose_msg=hash_js['verbose_msg'],
		md5=hash_js['resource'])
			return new_message
		else:
			basic_data = '''
<b>MD5: </b>{md5}
<b>Positives: </b>{positives}/70
<b>Scan date: </b>{scan_date}
'''.format(md5=hash_js['md5'],
		positives=hash_js['positives'],
		scan_date=hash_js['scan_date'])

			#print(basic_data)
			return basic_data

	except Exception as e:
		print('Error: ' + str(e))

#@run_async
def get_file_scan(bot, update):
	try:
		url = 'https://virustotal.com/vtapi/v2/file/scan'
		params = {'apikey':VIRUS_TOTAL_APIKEY}

		doc_info = bot.get_file(update.message.document.file_id)
		doc_info = str(doc_info)
		doc_info = doc_info.replace("'", '"')

		js = json.loads(doc_info)
		print(js)
		doc_id = js['file_id']
		doc_path = js['file_path']
		doc_name = js['file_path'].split('/')[-1]

		upload_file = download_file(doc_path, doc_name)
		open_file = open(doc_name, 'rb')
		files = {'file':(doc_name, open_file)}

		r = requests.post(url, files=files, params=params)
		open_file.close()
		file_js = json.loads(r.text)

		basic_data = '''
<b>{verbose_msg}</b>

<b>Scan ID: </b>{scan_id}
<b>SHA-1: </b>{sha1}
<b>SHA-256: </b>{sha256}
<b>MD5: </b>{md5}
'''.format(verbose_msg=file_js['verbose_msg'],
		scan_id=file_js['scan_id'],
		sha1=file_js['sha1'],
		sha256=file_js['sha256'],
		md5=file_js['md5'])

		#print(basic_data)
	
		button = [[InlineKeyboardButton('Access permalink', url=file_js['permalink'])]]
		button_link = InlineKeyboardMarkup(button)

		msg = bot.send_message(parse_mode='HTML', chat_id=update.message.chat_id, text=basic_data, reply_to_message_id=update.message.message_id, reply_markup=button_link)

		bot.edit_message_text(parse_mode='HTML', chat_id=update.message.chat_id, text=hash_scan(file_js['md5']), message_id=msg.message_id, reply_to_message_id=update.message.message_id, reply_markup=button_link)

		os.remove(doc_name)
	except Exception as e:
		print('Erro: ' + str(e))

def get_domain_scan(bot, update, args):
	try:
		#analyze a hash
		url = 'https://www.virustotal.com/vtapi/v2/url/scan'
		params = {'apikey':VIRUS_TOTAL_APIKEY,
				'url':args[0]}

		r = requests.post(url, data=params, headers={'Content-Type':'application/x-www-form-urlencoded'})
		url_js = json.loads(r.text)

		basic_data = '''
<b>{verbose_msg}</b>

<b>Scan ID: </b>{scan_id}
<B>Scan date: </b>{scan_date}
<b>URL: </b>{url}
'''.format(verbose_msg=url_js['verbose_msg'],
		scan_id=url_js['scan_id'],
		scan_date=url_js['scan_date'],
		url=url_js['url'])
	
		button = [[InlineKeyboardButton('Access permalink', url=url_js['permalink'])]]
		button_link = InlineKeyboardMarkup(button)

		bot.send_message(parse_mode='HTML', chat_id=update.message.chat_id, text=basic_data, reply_to_message_id=update.message.message_id, reply_markup=button_link)
	except IndexError:
		bot.send_message(parse_mode='HTML', chat_id=update.message.chat_id, text='<b>/url URL</b>', reply_to_message_id=update.message.message_id)

def get_hash_report(bot, update, args):
	try:
		#analyze a hash
		url = 'https://www.virustotal.com/vtapi/v2/file/report'
		params = {'apikey':VIRUS_TOTAL_APIKEY,
				'resource':args[0]}

		r = requests.get(url, params=params)

		hash_js = json.dumps(r.json())
		hash_js = json.loads(hash_js)
		print(hash_js)

		basic_data = '''
<b>MD5: </b>{md5}
<b>Positives: </b>{positives}/70
<b>Scan date: </b>{scan_date}
'''.format(md5=hash_js['md5'],
		positives=hash_js['positives'],
		scan_date=hash_js['scan_date'])

		button = [[InlineKeyboardButton('Access permalink', url=hash_js['permalink'])]]
		button_link = InlineKeyboardMarkup(button)

		bot.send_message(parse_mode='HTML', chat_id=update.message.chat_id, text=basic_data, reply_to_message_id=update.message.message_id, reply_markup=button_link)
	except IndexError:
		bot.send_message(parse_mode='HTML', chat_id=update.message.chat_id, text='<b>/hash HASH</b>', reply_to_message_id=update.message.message_id)

def main():
	updater = Updater(token=API_TOKEN)
	dispatcher = updater.dispatcher

	dispatcher.add_handler(CommandHandler('hash', get_hash_report, pass_args=True))
	dispatcher.add_handler(CommandHandler('help', get_help))
	dispatcher.add_handler(CommandHandler('url', get_domain_scan, pass_args=True))
	#dispatcher.add_handler(CallbackQueryHandler())

	#filtering documents
	dispatcher.add_handler(MessageHandler(Filters.document, get_file_scan))

	run(updater)

if __name__ == '__main__':
	main()
