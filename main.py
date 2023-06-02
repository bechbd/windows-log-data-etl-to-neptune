#https://csr.lanl.gov/data-fence/1684892433/RxnGQnlasr3kwqxLJngoZH4RblM=/cyber1/auth.txt.gz
#https://csr.lanl.gov/data-fence/1684892433/RxnGQnlasr3kwqxLJngoZH4RblM=/cyber1/proc.txt.gz
#https://csr.lanl.gov/data-fence/1684892433/RxnGQnlasr3kwqxLJngoZH4RblM=/cyber1/flows.txt.gz
#https://csr.lanl.gov/data-fence/1684892433/RxnGQnlasr3kwqxLJngoZH4RblM=/cyber1/dns.txt.gz
#https://csr.lanl.gov/data-fence/1684892433/RxnGQnlasr3kwqxLJngoZH4RblM=/cyber1/redteam.txt.gz

'''
(computer)-->(computer),  
(user)-->(computer), 
(process)-->(computer)  
'''
import pandas as pd
import uuid
import time
import os
import logging

PRINT_FREQUENCY = 5000000
BREAK_ON_LOOP = False
START_MILLIS = 150880
STOP_MILLIS = 2557050

input_path=f"./input"
output_path=f"./output"
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

computers = set()
users = set()
process = set()

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

def write_csv(df, filename):
    filename = f'{output_path}/{filename}'
    if not os.path.isfile(filename):
        df.to_csv(filename, index=False)
    else: # else it exists so append without writing the header
        df.to_csv(filename, mode='a', index=False, header=False)

def process_auth_csv(filename):
    logger.info(f"Processing {filename}")
    count=0
    bad=0
    login_event=[]
    login_edges=[]
    with open(f"{input_path}/{filename}", 'r') as input_file:
        for line in input_file:
            count += 1
            parts = line.replace("\n", "").split(",")
            if len(parts) != 9:                    
                logger.warning("We have a bad line, not enough parts")
                parts=None
            if int(parts[0]) >START_MILLIS and int(parts[0])<STOP_MILLIS:
                if parts and not '?' in parts[1] and not '?' in parts[2] and not '?' in parts[3] and not '?' in parts[4]:
                    users.add(parts[1])
                    users.add(parts[2])                
                    computers.add(parts[3])
                    computers.add(parts[4])
                    '''
                    0 time,
                    1 source user@domain,
                    2 destination user@domain,
                    3 source computer,
                    4 destination computer,
                    5 authentication type,
                    6 logon type,
                    7 authentication orientation,
                    8 success/failure'''                
                    
                    # Create Login Event
                    login_id = f"login_{count}"
                    login_event.append({
                        '~id': login_id, 
                        '~label': 'login', 
                        'time': parts[0] , 
                        'authentication_type': parts[5],
                        'logon_type': parts[6],
                        'authentication_orientation': parts[7],
                        'success': True if parts[8].lower()=='success' else False
                    })
                    
                    # Create Edges to source and destination users                
                    # Create edges to source and destination computers
                    login_edges.append({
                        '~id': uuid.uuid4(), 
                        '~label': 'login_by', 
                        '~from': parts[1], 
                        '~to': login_id,
                        'login_id': login_id,
                        'time': parts[0]
                    })
                    login_edges.append({
                        '~id': uuid.uuid4(), 
                        '~label': 'login_as', 
                        '~from': login_id, 
                        '~to': parts[2],
                        'login_id': login_id,
                        'time': parts[0]
                    })
                    login_edges.append({
                        '~id': uuid.uuid4(), 
                        '~label': 'login_from', 
                        '~from': parts[3], 
                        '~to': login_id,
                        'login_id': login_id,
                        'time': parts[0]
                    })
                    login_edges.append({
                        '~id': uuid.uuid4(), 
                        '~label': 'login_to', 
                        '~from': login_id, 
                        '~to': parts[4],
                        'login_id': login_id,
                        'time': parts[0]
                    })                
                else:
                    bad +=1                             
                
                if count%PRINT_FREQUENCY==0:
                    logger.info(f'Processing row {count} of {filename}')
                    df = pd.DataFrame(login_event)
                    df = df.rename(columns={"success": "success:Boolean", "time": "time:Long"})        
                    write_csv(df, 'login.csv')                    
                    login_event=[] 
                    df = pd.DataFrame(login_edges)        
                    write_csv(df, 'login_edges.csv')                                  
                    login_edges=[] 
                    if BREAK_ON_LOOP:
                        break
        logger.info(f"{bad} lines out of {count} ({(bad/count)*100}%) have missing data")
       
def process_dns_csv(filename):
    logger.info(f"Processing {filename}")
    count=0    
    data=[] 
    with open(f"{input_path}/{filename}", 'r') as input_file:
        for line in input_file:
            count += 1
            parts = validate_line_parts(line, 3)
            if parts:
                computers.add(parts[1])
                computers.add(parts[2])
                '''
                0 time,
                1 source computer,
                2 computer resolved
                '''
                data.append({
                    '~id': uuid.uuid4(), 
                    '~label': 'connected_to', 
                    '~from': parts[1], 
                    '~to': parts[2], 
                    'time': parts[0]
                })
            if count%PRINT_FREQUENCY==0:
                logger.info(f'Processing row {count} of {filename}')
                df = pd.DataFrame(data)     
                df = df.rename(columns={"time": "time:Long"})        
                write_csv(df, 'connected_to.csv')                                                  
                data=[]  
                if BREAK_ON_LOOP:
                    break      
        
def process_proc_csv(filename):
    logger.info(f"Processing {filename}")
    count=0
    data=[] 
    with open(f"{input_path}/{filename}", 'r') as input_file:
        for line in input_file:
            count += 1
            parts = validate_line_parts(line, 5)
            if parts:
                users.add(parts[1])
                computers.add(parts[2])
                process.add(parts[3])
                '''
                0 time,
                1 user@domain,
                2 computer,
                3 process name,
                4 start/end'''                
                
                data.append({
                    '~id': f"{parts[1]}_{parts[2]}_{parts[3]}_{parts[0]}", 
                    '~label': 'run_on', 
                    '~from': parts[3], 
                    '~to': parts[2], 
                    'start_time': parts[0] if parts[4].lower()=='start' else None ,  
                    'start_user': parts[1] if parts[4].lower()=='start' else None , 
                    'end_time': parts[0] if parts[4].lower()=='end' else None , 
                    'end_user': parts[1] if parts[4].lower()=='end' else None
                })
            
            if count%PRINT_FREQUENCY==0:
                logger.info(f'Processing row {count} of {filename}')                
                df = pd.DataFrame(data)     
                df = df.rename(columns={"start_time": "start_time:Long", "end_time": "end_time:Long"})  
                write_csv(df, 'run_on.csv')                            
                data=[]                 
                if BREAK_ON_LOOP:
                    break

def process_flows_csv(filename):
    logger.info(f"Processing {filename}")
    count=0
    data=[] 
    with open(f"{input_path}/{filename}", 'r') as input_file:
        for line in input_file:
            count += 1
            parts = validate_line_parts(line, 9)
            if parts:
                computers.add(parts[2])
                computers.add(parts[4])
                '''
                0 time,
                1 duration,
                2 source computer,
                3 source port,
                4 destination computer,
                5 destination port,
                6 protocol,
                7 packet count,
                8 byte count
                '''
                data.append({
                    '~id': uuid.uuid4(), 
                    '~label': 'requested', 
                    '~from': parts[2], 
                    '~to': parts[4], 
                    'time': parts[0], 
                    'duration': parts[1], 
                    'source_port': parts[3], 
                    'destination_port': parts[5], 
                    'protocol': parts[6], 
                    'packet_count': parts[7], 
                    'byte_count': parts[8], 
                })
            
            if count%PRINT_FREQUENCY==0:
                logger.info(f'Processing row {count} of {filename}')
                df = pd.DataFrame(data)     
                df = df.rename(columns={"time": "time:Long", "duration": "duration:Long", 
                    "packet_count": "packet_count:Long", "byte_count": "byte_count:Long"})  
                write_csv(df, 'requested.csv')                                          
                data=[]
                
                if BREAK_ON_LOOP:
                    break

def process_redteam_csv(filename):
    logger.info(f"Processing {filename}")
    count=0
    
    redteam_event=[]
    redteam_edges=[]
    with open(f"{input_path}/{filename}", 'r') as input_file:
        for line in input_file:
            count += 1
            parts = validate_line_parts(line, 4)
            if parts:
                users.add(parts[1])
                computers.add(parts[2])
                computers.add(parts[3])
                '''
                0 time,
                1 user@domain,
                2 source computer,
                3 destination computer
                '''
                # Create Red Team, Event
                redteam_id = uuid.uuid4()
                redteam_event.append({
                    '~id': redteam_id, 
                    '~label': 'redteam', 
                    'time': parts[0]
                })
                
                # Create Edges to users                
                # Create edges to source and destination computers
                redteam_edges.append({
                    '~id': uuid.uuid4(), 
                    '~label': 'event_by', 
                    '~from': parts[1], 
                    '~to': redteam_id
                })
                redteam_edges.append({
                    '~id': uuid.uuid4(), 
                    '~label': 'compromised', 
                    '~from': redteam_id, 
                    '~to': parts[3] 
                })
                redteam_edges.append({
                    '~id': uuid.uuid4(), 
                    '~label': 'triggered', 
                    '~from': parts[2], 
                    '~to': redteam_id
                })
        df = pd.DataFrame(redteam_event)
        df = df.rename(columns={"time": "time:Long"})           
        write_csv(df, 'redteam.csv')                                                     
        redteam_event=[] 
        df = pd.DataFrame(redteam_edges)  
        write_csv(df, 'redteam_edges.csv')                                                          
        redteam_edges=[] 

def output_computers():
    df = pd.DataFrame(computers, columns=['~id'])
    df['~label']='computer'
    write_csv(df, 'computers.csv')   
    
def output_users():
    df = pd.DataFrame(users, columns=['~id'])
    df['~label']='user'
    write_csv(df, 'users.csv')   

def output_processes():
    df = pd.DataFrame(process, columns=['~id'])
    df['~label']='process'
    write_csv(df, 'processes.csv')   

def main():
    # Remove all existing files
    dir = 'path/to/dir'
    for f in os.listdir(output_path):
        os.remove(os.path.join(output_path, f))
    tic = time.perf_counter()       
    #process_dns_csv('dns.txt')
    process_auth_csv('auth.txt')
    #process_proc_csv('proc.txt')
    #process_flows_csv('flows.txt')
    #process_redteam_csv('redteam.txt')
    toc = time.perf_counter()
    logger.info(f"Processing files in {(toc - tic)/60:0.4f} mins")
    output_computers()
    output_users()
    output_processes()
    


    
if __name__ == "__main__":
    main()