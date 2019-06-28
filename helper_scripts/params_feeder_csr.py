import json
import sys

def dump_c_parameters(params):
    with open(params['c_params_file_path'], 'w') as fout:
        print(params["csr_path"],               file=fout)
        print(params["ext_file_path"],          file=fout)
        print(params["output_cert_path"],       file=fout)
        print(params["startDateASN1"],          file=fout)
        print(params["endDateASN1"],            file=fout)
        print(params["serial"],                 file=fout)
        print(int(params["x509v3"]),            file=fout)
        print(params["ca_cert_path"],           file=fout)
        print(params["engine_path"],            file=fout)
        print(int(params["load_ecengine"]),     file=fout)
        print(int(params["debug"]),             file=fout)

def load_json(path):
    try:
        with open(path, 'r') as fin:
            print ("INFO: Preparing parameters file ", path, " for c codes ...")
            obj = json.load(fin)
            return obj
    except IOError as e:
        print("ERROR: could not open parameters file ", path, file=sys.stderr)
        return None
    except json.decoder.JSONDecodeError as e:
        print("ERROR: could not parse parameters file as json ", file=sys.stderr)
        return None

def main(argv):
    params_obj = load_json(argv[1])
    if not params_obj:
        return 1

    try:
        dump_c_parameters(params_obj)
    except IOError as e:
        print("ERROR: could not write out c parameters file ", obj['c_params_file_path'], file=sys.stderr)
        return 1
    print ("INFO: Conversion is done!")
    return 0

exit(main(sys.argv))
