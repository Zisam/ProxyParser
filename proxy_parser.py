# coding=utf-8
# github.com/Zisam/ProxyParser
import os
import sys
import pandas as pd
pd.options.mode.chained_assignment = None
import random
import requests
import re
import threading
from tqdm import tqdm

HOME_FOLDER = os.path.dirname(__file__)

class ProxyParser:
	def __init__(self,sites=['gatherproxy','free_proxy','socks_proxy','sslproxies','usproxy']):
		self.sites = sites
		self.functions = {
			'gatherproxy':self.get_from_gatherproxy,
			'free_proxy':self.get_from_free_proxy_list,
		    'socks_proxy':self.get_from_socks_proxy,
		    'sslproxies':self.get_from_sslproxies,
		    'usproxy':self.get_from_usproxy
		}
		self.user_agents = self.load_user_agents()
		self.proxies = self.get_proxies()
		self.proxies_tested = self.test_proxies()
		self.save_to_txt()

	@staticmethod
	def load_user_agents():
		try:
			user_agents = open(os.path.join(HOME_FOLDER, 'user_agents.txt'), 'r').read().split('\n')
		except Exception as e:
			user_agents = None
		return user_agents

	def save_to_txt(self):
		self.proxies_tested.to_csv(os.path.join(HOME_FOLDER, 'proxies.txt'), header=False, index=False, sep=':', mode='w')
		print('Saved to proxies.txt ')

	def get_proxies(self):
		print('Loading proxies...')
		proxy_sub_tables = []
		for site in tqdm(self.sites):
			if site in self.functions.keys():
				proxy_sub_table = self.functions[site]()
				proxy_sub_tables.append(proxy_sub_table)
		proxy_table = pd.concat(proxy_sub_tables, ignore_index=True)
		proxy_table.drop_duplicates(inplace=True)
		print('Got ' + str(len(proxy_table.index.values)) + ' proxies. ')
		return proxy_table
	
	def test_proxies(self):
		proxies_tested = []
		
		def test_table():
			ths = []
			for index,row in self.proxies.iterrows():
				th = threading.Thread(target=test_one_proxy, args=[row])
				ths.append(th)
			for th in ths:
				while True:
					num_threads = threading.activeCount()
					if num_threads <= 400:
						th.start()
						break
			for th in tqdm(ths):
				th.join()
		
		def test_one_proxy(row):
			link = 'http://check.zennolab.com'
			proxy_ip = str(row.values[0]) + ':' + str(int(row.values[1]))
			headers = {'user-agent': random.choice(self.user_agents), 'Connection': 'Keep-Alive'}
			try:
				requests.get(link, proxies={"http": "http://" + proxy_ip, "https": "https://" + proxy_ip}, timeout=10, headers=headers)
			except requests.exceptions.RequestException as e:
				return
			else:
				proxies_tested.append(row.values)

		print('Testing proxies...')
		test_table()
		proxy_table = pd.DataFrame(data=proxies_tested,columns=self.proxies.columns)
		print(str(len(proxy_table.index.values)) + '/'+str(len(self.proxies.index.values))+' proxies passed the test. ')
		return proxy_table
	
	def get_from_gatherproxy(self):
		ips = []
		ports = []
		for pagenum in range(20):
			try:
				data = 'Type=elite&PageIdx=' + str(pagenum) + '&Uptime=0'
				headers = {'user-agent': random.choice(self.user_agents), 'Connection': 'Keep-Alive'}
				headers['Content-Type'] = 'application/x-www-form-urlencoded'
				req = requests.post('http://gatherproxy.com/proxylist/anonymity/?t=Elite', headers=headers, data=data)
				content = req.text
			except Exception as e:
				print(str(e))
				break
			else:
				ips_loc = re.findall('\"PROXY_IP\":\"(\d+.\d+.\d+.\d+)\"', content)
				ports_loc = re.findall('\"PROXY_PORT\":\"(.+?)\"', content)
				ports_loc = [int("0x" + x, 16) for x in ports_loc]
				ips.extend(ips_loc)
				ports.extend(ports_loc)
		proxy_table = pd.DataFrame(data={'IP Address': ips, 'Port': ports})
		return proxy_table
	
	@staticmethod
	def get_content(url):
		try:
			req = requests.get(url)
		except Exception as e:
			print(str(e))
		else:
			return req.text
	
	@staticmethod
	def html_to_df(content):
		tables = pd.read_html(content)
		proxy_table = tables[0]
		proxy_table = proxy_table[['IP Address', 'Port']][:-1]
		proxy_table[['Port']] = proxy_table[['Port']].astype(int)
		return proxy_table
	
	@classmethod
	def get_from_url(cls,url):
		content = cls.get_content(url)
		proxy_table = cls.html_to_df(content)
		return proxy_table
	
	@classmethod
	def get_from_free_proxy_list(cls):
		url = 'https://free-proxy-list.net'
		proxy_table = cls.get_from_url(url)
		return proxy_table
	
	@classmethod
	def get_from_sslproxies(cls):
		url = 'https://www.sslproxies.org'
		proxy_table = cls.get_from_url(url)
		return proxy_table
	
	@classmethod
	def get_from_usproxy(cls):
		url = 'https://www.us-proxy.org'
		proxy_table = cls.get_from_url(url)
		return proxy_table
	
	@classmethod
	def get_from_socks_proxy(cls):
		url = 'https://www.socks-proxy.net'
		proxy_table = cls.get_from_url(url)
		return proxy_table

def main():
	pp = ProxyParser()
	
if __name__=='__main__':
	main()
