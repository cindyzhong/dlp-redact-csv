# dlp-redact-csv
Redact CSV files from Local using Google DLP 


Cautions:
- This is a sample code that is meant for quickly redacting small files.
- Test the code for <10000 records first before making DLP calls on the entire file
- In order to make the code work, you will need a header row to the CSV file
- If you encounter issues with quota, consider chucking the files into smaller files and put sleep time between making the DLP Requests.
- Depending on the format of your file, some preprocessing might be required 

https://cloud.google.com/dlp/limits
