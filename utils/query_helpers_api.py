import requests
import os
from dotenv import load_dotenv

load_dotenv()

API_BASE_URL = "https://ssh-integration.vercel.app"
BEARER_TOKEN = "w73IXAcg9Dn3ROMlV68stJZZ"

HEADERS = {
    "Authorization": f"Bearer {BEARER_TOKEN}"
}

#add validated with APITest1
def add_part(part_number):
    url = f"{API_BASE_URL}/Add"
    data = {"partnumber": part_number}
    response = requests.post(url, data=data, headers=HEADERS)
    return response.text

#filter validated with 'Manufacturer' & 'YAGEO'
def filter_parts(category, value):
    url = f"{API_BASE_URL}/Filter"
    data = {"filter": category, "limitby": value}
    response = requests.post(url, data=data, headers=HEADERS)
    return response.json()

#sort validated with all fields
def sort_parts(sort):
    url = f"{API_BASE_URL}/Sort"
    data = {"sort": sort}
    response = requests.post(url, data=data, headers=HEADERS)
    return response.json()


def tag_part(part_number, tag):
    url = f"{API_BASE_URL}/Tag"
    data = {"partnumber": part_number, "tag": tag}
    response = requests.post(url, data=data, headers=HEADERS)
    return response.text

#update validated with input 0-5
def update_part(lower, upper):
    url = f"{API_BASE_URL}/Update"
    data = {"lower": lower, "upper": upper}
    response = requests.post(url, data=data, headers=HEADERS)
    return response.text

def delete_part(category, delete):
    url = f"{API_BASE_URL}/Delete"
    data = {"category": category, "delete": delete}
    response = requests.post(url, data=data, headers=HEADERS)
    return response.text
