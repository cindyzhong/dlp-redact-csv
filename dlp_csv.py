def deidentify_csv(
    project,
    input_csv_file=None,
    output_csv_file=None,
    field_to_be_redacted=None,
    info_types=None,
    service_account_path=None
):
    """Uses the Data Loss Prevention API to deidentify dates in a CSV file by
        pseudorandomly shifting them.
    Args:
        project: The Google Cloud project id to use as a parent resource.
        input_csv_file: The path to the CSV file to deidentify. The first row
            of the file must specify column names, and all other rows must
            contain valid values.
        output_csv_file: The path to save the date-shifted CSV file.
        field_to_be_redacted: The list of (date) fields in the CSV file to redact.
            Example: ['Text']
        info_types: List of Infotypes to Redact
            Example: ['AGE','PASSWORD','FIRST_NAME']
    Returns:
        None; the response from the API is printed to the terminal.
    """
    # Import the client library
    import google.cloud.dlp

    # Instantiate a client
    dlp = google.cloud.dlp_v2.DlpServiceClient.from_service_account_json(service_account_path)

    # Convert the project id into a full resource id.
    parent = f"projects/{project}"

    # Convert the field to be redacted to Protobuf type
    def map_fields(field):
        return {"name": field}

    if field_to_be_redacted:
        field_to_be_redacted = list(map(map_fields, field_to_be_redacted))
    else:
        field_to_be_redacted = []

    # Read and parse the CSV file
    import csv

    f = []
    with open(input_csv_file, "r") as csvfile:
        reader = csv.reader(csvfile,delimiter = "|")
        for row in reader:
            f.append(row)

    #Helper function for converting CSV rows to Protobuf types
    def map_headers(header):
        return {"name": header}

    def map_data(value):
        return {"string_value": value}

    def map_rows(row):
        return {"values": map(map_data, row)}


    # Using the helper functions, convert CSV rows to protobuf-compatible
    # dictionaries.
    csv_headers = map(map_headers, f[0])
    csv_rows = map(map_rows, f[1:])


    # Construct the table dict
    table_item = {"table": {"headers": csv_headers, "rows": csv_rows}}


    # Write to CSV helper methods

    def write_header(header):
        return header.name

    def write_data(data):
        return data.string_value

 
    # Construct inspect configuration dictionary
    inspect_config = {"info_types": [{"name": info_type} for info_type in info_types]}

    #Construct deidentify configuration dictionary
    deidentify_config = {
        "record_transformations": {
            "field_transformations": [
                {
                    "fields": field_to_be_redacted,
            "info_type_transformations": {
                "transformations": [
                    {
                        "primitive_transformation": {
                        "replace_with_info_type_config": {}
                        }
                    }
            ]
        },
                }
            ]
        }
    }


    # Call the API
    response = dlp.deidentify_content(
        parent,
        inspect_config=inspect_config,
        deidentify_config=deidentify_config,
        item=table_item
    )

    # Write results to CSV file
    with open(output_csv_file, "w") as csvfile:
        write_file = csv.writer(csvfile, delimiter="|")
        write_file.writerow(map(write_header, response.item.table.headers))
        for row in response.item.table.rows:
            write_file.writerow(map(write_data, row.values))
    # Print status
    print("Successfully saved redacted output to {}".format(output_csv_file))

####################### MODIFY YOUR VARIABLES ##############################################

project='cindy-analytics-demos'
info_types=['AGE','PASSWORD','FIRST_NAME']
input_csv_file='/Users/cindyzhong/myscripts/dlp-demo/dlp_demo.csv'
output_csv_file='/Users/cindyzhong/myscripts/dlp-demo/dlp_output.csv'
field_to_be_redacted=['Text']
service_account_path="/Users/cindyzhong/mykeys/PATH_TO_KEY.json"
###########################################################################################


deidentify_csv(project,input_csv_file,output_csv_file,field_to_be_redacted,info_types,service_account_path)
