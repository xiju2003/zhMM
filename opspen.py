import  os
from    lib.data    import OPSPEN_PATH, POCS_PATH, EXPS_PATH, POCS
#from    lib.data    import OS_INFO, CPU_TYPE
#from    lib.term    import cooloutput
from    lib.loader  import load_string_to_module

'''thirdparty modules '''
import  argparse
import  sys

def end():
    print("see you again, babe.")
    exit(0)

def initialize(config: dict):
    ''' process the configuration and load pocs

    e.g.1  config = {
        2      "url": "https://nohere.com",
        3      "do_exp": True,
        4      "pick_vuln": ["CVE-2016-4437", "..."],
        5      "ban_vuln": []"
        6  }
        7  initialize(config)
    '''
    
    if config["url"] is None and config["file"] is None:
        ## if user didn't appoint a url or a file, we should exit, in'it??
        print("ERROR: should appoint a url or a file of target(s).")
        end()

    #if config["pick_vuln"] is not None:
    #    PICKED  =   config.get("pick_vuln",[])
    #elif config["ban_vuln"] is not None:
    #    BANED   =   config.get("ban_vuln",[])
    
    _pocs   =   []
    for root, dirs, files in os.walk(POCS_PATH):
        files = filter(lambda x : not x.startswith("__") and x.endswith(".py") and x not in config.get("ban_vuln", []), files)
        _pocs.extend(map(lambda x: os.path.join(root,  x), files))

    for poc in _pocs:
        with open(poc, 'r') as f:
            print("loading " + poc + "......", end='')
            module = load_string_to_module(f.read())
            print("done")
            POCS.append(module)

     
def start(config: dict):
    url_list    =   config.get("url", [])
    for i in url_list:
        for poc in POCS:
            try:
                result  =   poc.verify()
            except Exception as e:
                result  =   None
                print("Error: " + str(e))
            if result:
                print("++ vulnerability detected in url: {} ".format(i), end='')
                if result["exploit"] is not None and result["do_exp"] is True:
                    print("ops! Exploitation script found, will execute.")
                    
                    with open(result["exploit"], 'r') as exp_tmp:
                        exp_code = exp_tmp.read()
                        exp_module = load_string_to_module(exp_code)
                        exp_module.attack(config)
                else:
                    print()

def main():
    parser  =   argparse.ArgumentParser()
    parser.add_argument("-u", "--url", type=str, help="single url scan.")
    parser.add_argument("-f", "--file", type=str, help="target file list")
    parser.add_argument("-d", "--doexploit", type=bool, help="do exploit after dicover the vuln or not.", default=True)
    args    =   parser.parse_args()
    
    config = {
            "url": None,
            "file": None,
            "do_exp": True
            }
    if args.url is not None:
        config["url"] = args.url
    if args.file is not None:
        config["file"] = args.file
    
    print("Welcome to opspen.")
    #print("OS infomation: " + str(OS_INFO))
    #print("CPU type     : " + str(CPU_TYPE))
    print("loading proot_of_concept and exploit scritps...")
    initialize(config)

    print()
    print("Starting ... ")
    start(config)
main()
