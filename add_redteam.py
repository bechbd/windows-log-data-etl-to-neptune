import awswrangler as wr
import logging
import time
import pandas as pd

input_path=f"./input"
output_path=f"./output"
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

def validate_line_parts(line, expected_num_fields):
    if '?' in line:
        logger.info(f"Ignoring line due to a '?' {line}")
        return None
    else:
        parts = line.replace("\n", "").split(",")
        if len(parts) != expected_num_fields:                        
            logger.warning("We have a bad line, not enough parts")
            return None
        else:
            return parts

def process_redteam_csv(filename, client):
    logger.info(f"Processing {filename}")
    with open(f"{input_path}/{filename}", 'r') as input_file:
        for line in input_file:
            parts = validate_line_parts(line, 4)
            if parts:
                '''
                0 time,
                1 user@domain,
                2 source computer,
                3 destination computer
                '''
                df = wr.neptune.execute_opencypher(client, f"""
                    MATCH p=(computer)-[:login_from]->(r:login)<-[:login_by]-(user)
                    where r.time={parts[0]} and id(computer)='{parts[2]}' and id(user)='{parts[1]}'
                    RETURN p
                    """)
                if df.shape[0] == 1:
                    f = None
                else:
                    logger.warning(f"No login found for {line}")
            #print(line)


def main():
    url='' # The Neptune Cluster endpoint
    iam_enabled = False # Set to True/False based on the configuration of your cluster
    neptune_port = 8182 # Set to the Neptune Cluster Port, Default is 8182
    client = wr.neptune.connect(url, neptune_port, iam_enabled=iam_enabled)
    print(client.status())
    tic = time.perf_counter()       
    process_redteam_csv('redteam.txt', client)
    toc = time.perf_counter()
    logger.info(f"Processing files in {(toc - tic)/60:0.4f} mins")
    
if __name__ == "__main__":
    main()