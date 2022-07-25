# AWS L0 transmission (L0tx) processing
 
Receive and decode transmissions from PROMICE automatic weather stations.


## Quickstart

The `tx.py` script contains all objects and functions for processing transmissions. A full workflow is available to run in `getL0tx.py`, which imports from `tx.py`. Credentials are needed to access emails - `accounts.ini`, `credentials.ini` - along with a list of modem numbers and names (`imei2name.ini`).

Some basic unit testing is available with `tx.py`, which can be executed by running the `tx.py` script or running the unit test from command line:

```
python -m unittest tx.py
```

## Workflow design

The workflow in `tx.py` fetches messages over IMAP sent from the Iridium SBD service. These messages are decoded from the binary format transmitted by the AWS, and appends each dataline to the corresponding station that transmitted it (based on the modem number, `imei`). 

The workflow is object-oriented to handle each component needed to fetch and decode messages.

![tx_workflow](https://raw.githubusercontent.com/GEUS-Glaciology-and-Climate/awsrx/obj/figs/tx_design.png)

1. `PayloadFormat` handles the message types and formatting templates. These can be imported from file, with the two .csv files in the `payload_formatter` currently used. These used to be hardcoded in the script, but it seemed more appropriate to store them in files

2. `SbdMessage` handles the SBD message, either taken from an `email.message.Message` object or a .sbd file (half completed, still being developed)

3. `EmailMessage` handles the email message (that the SBD message is attached to) to parse information such as sender, subject, date, and to check for attachments. The `EmailMessage` inherits from the `SbdMessage` object, as the SBD message is part of the email. Previously this was the opposite which, although followed the workflow steps, was unintuitive for the object-oriented workflow design

4. `L0tx` handles the processing and output of the L0 transmission dataline. This object inherits from `EmailMessage` and `PayloadFormat` to read and decode messages


To reprocess old messages, these can be retrieved from the mailbox by rolling back the counter in `last_aws_uid.ini` or by reading from .sbd file.


## Future development

![pypromice](https://raw.githubusercontent.com/GEUS-Glaciology-and-Climate/awsrx/obj/figs/pypromice_prelim.png)

The `tx.py` script here will form a module as part of a bigger package. This package will be the go-to tool for handling and processing PROMICE and GC-Net datasets, available through pip and conda-forge, perhaps even across platforms such as R and Matlab. For now, I think a good name would be `pypromice`, but this is open for suggestions. Functionality would be pulled and compiled from many repositories, including:

- Fetching AWS L0 transmissions
- AWS L0 >> L3 processing - [PROMICE-AWS-processing](https://github.com/GEUS-Glaciology-and-Climate/PROMICE-AWS-processing)
- Post-processing AWS L3 data, including flagging, filtering and fixing - [PROMICE-AWS-toolbox](https://github.com/GEUS-Glaciology-and-Climate/PROMICE-AWS-toolbox), [GC-Net-level-1-data-processing](https://github.com/GEUS-Glaciology-and-Climate/GC-Net-level-1-data-processing)
- WMO data processing into BUFR formats for operational ingestion - [csv2bufr](https://github.com/GEUS-Glaciology-and-Climate/csv2bufr)
- Retrieving PROMICE/GC-Net datasets from Dataverse/online, with no downloading - [PROMICE](https://github.com/GEUS-Glaciology-and-Climate/PROMICE)
 
 
## To-do

- [X] Migrate workflow to Python 3.x

- [X] Re-structure workflow and migrate hard-coded attributes to file

- [X] Finalise and check initialising `SbdMessage` and `EmailMessage` from email file

- [ ] Check the `RAWtoSTR` decoder function. The other decoder functions (`GFP2toDEC` and `GLI4toDEC`) have been migrated and tested, but I have yet to come across a message that requires the `RAWtoSTR` decoder.

- [ ] Clean up the `L0tx.getDataLine()` function, as this is pretty long-winded. This function does all of the decoding of an SBD message payload (`SBDmessage.payload`), and was migrated from the old `AWSmessage.parse_aws()` function

- [ ] As well as relying on IMEI numbers, we could identify which stations is transmitting by looking at `SbdMessage.unit_location`

- [ ] Decide whether a CR1000 logger program should be used to define the transmitted message. This used to be half-implemented to detect the data field in the received message, and then was only used for adding column header names to the outputted datalines (and wasn't 100% reliable) 

- [ ] `Payload.payload_type` currently defines the character (e.g. `t`, `f`) within a message, along with the number of bytes per character. In the script, information such as NaN values, formatting and processing occurs based on the character. Instead of being in the script, these could be defined in the `payload_type.csv` file and become part of the `PayloadFormat` object

- [ ] Take the `PayloadFormatter` attributes `Payload.payload_format` and `Payload.payload_type` out of dictionary types (`dict`), and retain the key values as individual attributes where possible. This has been done with the `Emailmessage` and `SBDmessage` objects already, and makes it easier and more accessible for fresh eyes 


