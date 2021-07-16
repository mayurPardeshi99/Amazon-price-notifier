import requests
from requests.exceptions import MissingSchema
from bs4 import BeautifulSoup
import lxml

headers = {
    "Accept-Language": "en-US,en;q=0.9",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.106 Safari/537.36",
}


class Fetch_Price:

    def __init__(self, url):
        self.product_url = url

    def get_data(self):
        try:
            response = requests.get(url=self.product_url, headers=headers)
            response.raise_for_status()

            soup = BeautifulSoup(response.text, "lxml")

            try:
                price_str = soup.find(name="span", id="priceblock_ourprice").getText()
            except SyntaxError:
                price_str = soup.find(name="span", id="priceblock_dealprice").getText()
            except AttributeError:
                try:
                    price_str = soup.find(name="span", id="priceblock_dealprice").getText()
                except (AttributeError, TypeError):
                    price_str = "n NA"

            img_src = soup.find(name="img", id="landingImage")["src"]
            product_name = soup.find(name="span", id="productTitle").getText().strip()
            try:
                price = price_str.split()[1]
            except IndexError:
                if "₹" in price_str:
                    price = price_str.replace("₹", "")
                else:
                    price = price_str.replace("$", "")

            data = {
                "name": product_name,
                "price": price,
                "img_src": img_src,
                "url": self.product_url
            }
            return data
        except MissingSchema:
            return False
        except:
            return False
