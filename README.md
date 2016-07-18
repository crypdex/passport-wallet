# Passport wallet

## Features

The `render-page.py` script generates a secure paper wallet for *any* crypto-currency.

* No need to hide your paper wallets! The Passport paper wallet is AES encrypted.
* Key stretching makes brute force attempts at cracking impractical.
* Data is represened as a sequence of English words making it easy to enter without errors.

## Sample usage

You must provide at minimum the currency symbol, a public address, and
a private key:

![alt text](images/sample-usage-render.png)

![alt text](images/sample-page-btc.png)

For help on the different options, run: `render-page.py -h`

Use `recover-key.py` to recover the private key. Just enter the word sequence and your password:

![alt text](images/sample-usage-recover.png)


## Notes

The output of `render-page.py` is a single PNG file with design elements similar to a page in a passport. The color scheme is automatically derived from the colors in the currency logo. *Any* crypto-currency address can be represented since the encryption step is generic. The ideal use case for the Passport wallet is: secure cold-storage for a portfolio of crypto-currencies where the wallets themselves can be viewed by others without compromising security.

![alt text](images/sample-page-ltc-thumbnail.png)
![alt text](images/sample-page-sjcx-thumbnail.png)
![alt text](images/sample-page-eth-thumbnail.png)
![alt text](images/sample-page-ppc-thumbnail.png)
![alt text](images/sample-page-emc-thumbnail.png)
