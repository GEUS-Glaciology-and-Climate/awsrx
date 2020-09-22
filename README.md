# awsrx
Receive and decode transmissions from PROMICE automatic weather stations and other GEUS instruments.

## Overview
Fetches emails every 30 minutes over IMAP looking for messages from the Iridium SBD service, decodes the binary format transmitted by the AWS, and appends each record to the csv file of the station that transmitted it. It also decodes messages sent by the old GPS trackers from Alberto Behar, in case we still have any working unit, but that needs a proprietery Windows-only binary not included here. It can be extended to support any other kind of instrument where data comes in as emails. The `EmailMessage` class can parse the headers of any email, like sender, subject, date and attachments. It has an `SbdMessage` subclass knowing how to identify an Iridium SBD message among unrelated messages in the mailbox parse all information, both the transmitted payload and what is generated by the Iridium satellite like transmitter coordinate, [see some error plots](https://www.wmo.int/pages/prog/amp/mmop/documents/dbcp/Dbcp32/presentations/06_Meldrum_Iridium_Loc_QC.pdf). So instead of relying on IMEI numbers we could identify which station is transmitting by looking at `SbdMessage.data['sbd_data']['unit_location']` after discarding the occasional messages with large `SbdMessage.data['sbd_data']['cep_radius']`. Finally the `TrackerMessage` and `AwsMessage` subclasses of `SbdMessage` know how to decode the transmitted binary data attached to the email.

To run, a directory named `aws_data` must exist where the csv files will be written. If a `logger_programs` directory exists and it contains a  CR1000 logger program using Tx memory tables to define the transmitted message, there is a half-implemented functionality to detect the data field in the received message. But this is currently only used for adding column header names to the csv files and it may not be 100% reliable. The actual decoding is still based on the hardcoded formats found below the comment:
```
*** START OF MESSAGE FORMAT SPECIFICATIONS FOR NORMAL USERS ***
```

To reprocess old messages still in the mailbox just roll back the counter in `last_aws_uid.ini` but there is no provision for loading messages from disk. To do this, create an instance of `email.message.Message` from a file or on-disk mailbox using the functionality in the standard library and pass it to `AwsMessage.init()` object or any subclass of `EmailMessage`. Note that `EmailMessage` here is my own class, unfortunately named the same as the `email.message.EmailMessage` class introduced with the python3 standard library.

After all emails since the last successful check have been fetched and decoded, it is possible to automatically upload selected files to some ftp, this is partly still hardcoded but fetches account details from two `accoints.ini` and `credentials.ini` files. They are just templates in this repo.

If reworking this into our future workflow, the only important parts to carry are the `EmailMessage`, `SbdMessage` and `AwsMessage` classes, which I think are completely independent from the rest of the code. This is python 2.7 only, porting to 3.x may need some care in `AwsMessage.GLI4toDEC()`, `v.GFP2toDEC()`, `AwsMessage.RAWtoSTR()`and a few lines in the old messy `AwsMessage.parse_aws()`. It has always been run on Windows, some years ago I make it run on FreeBSD but further changes since then may have broken it again, e.g. L1347 will fail. There are no dependencies outside the standard library except for the optional [certifi](https://pypi.org/project/certifi) package.