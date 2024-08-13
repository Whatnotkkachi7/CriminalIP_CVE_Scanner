from rich import print
from rich.table import Table
from rich.console import Console
from rich.panel import Panel
from art import *
import logging
from rich.logging import RichHandler
import requests
import ipaddress

def check_api_key(key):
	url = "https://api.criminalip.io/v1/user/me"
	payload = {}
	headers = {
		"x-api-key": key
	}
	response = requests.request("POST", url, headers=headers, data=payload)
	try:
		if response.status_code != 200:
			return False, None
		response = response.json()
		name = response["data"]["name"]
		return True, name
	except:
		return False, None

def check_ip(ip):
	try:
		ipaddress.ip_address(ip)
		return True
	except ValueError:
		return False

def cve_scan(key, ip, console):
	url = f"https://api.criminalip.io/v1/asset/ip/report?ip={ip}"
	payload = {}
	headers = {"x-api-key": key}
	response = requests.request("GET", url, headers=headers, data=payload)
	data = response.json()["vulnerability"]["data"]
	table = Table(title="CVE Scan Result")
	table.add_column("CVE ID", justify="left", no_wrap=True)
	table.add_column("CVSSV Score", justify="center")
	table.add_column("Port", justify="left")
	table.add_column("APP", justify="left")
	cve_list = []
	for i in data:
		cve_list.append((i["cve_id"], i["cvssv3_score"], i["open_port_no_list"]["TCP"], i["app_name"]))
	cve_list = sorted(cve_list, key=lambda x: x[1], reverse=True)
	for i in cve_list:
		cve_id = i[0]
		cvssv_score = i[1]
		open_port = i[2]
		app = i[3]
		if cvssv_score >= 7.0:
			table.add_row(f"[red]{cve_id}[/red]", f"[red]{cvssv_score}[/red]", f"[red]{open_port}[/red]", f"[red]{app}[/red]")
		elif cvssv_score <= 3.0:
			table.add_row(f"[green]{cve_id}[/green]", f"[green]{cvssv_score}[/green]", f"[green]{open_port}[/green]", f"[green]{app}[/green]")
		else:
			table.add_row(f"[yellow]{cve_id}[/yellow]", f"[yellow]{cvssv_score}[/yellow]", f"[yellow]{open_port}[/yellow]", f"[yellow]{app}[/yellow]")
	if len(cve_list) > 0:
		console.print(table, justify="center")
	return len(cve_list)

def main():
	logging.basicConfig(
		 format="%(message)s", datefmt="[%X]", handlers=[RichHandler()]
	)

	log = logging.getLogger("rich")
	console = Console()
	console.clear()
	console.print(
		Panel(f"[red]{text2art("CVE SCANNER", "doom")}[/red]\n[bold blue]with Criminal IP", style="bold"), justify="center", style="bold"
	)
	API_KEY = input("Please type your Criminal IP API Key : ")
	check = check_api_key(API_KEY)
	if check[0] == False:
		log.critical("INVALID KEY OR SERVER ERROR")
		exit(1)
	print(f"Welcome [cyan]{check[1]}[/cyan]!!")
	IP = input("Please type IP : ")
	if check_ip(IP) == False:
		log.critical("INVALID IP")
	cnt_cve = cve_scan(API_KEY, IP, console)
	if cnt_cve == 0:
		print("🎉 no vulnerability 🎉")


if __name__ == "__main__":
	main()