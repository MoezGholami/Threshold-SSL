import json
import sys

def dump_c_parameters(params):
    sbj = params["subject"]
    with open(params['c_params_file_path'], 'w') as fout:
        print(params["serial"],             file=fout)
        print(params["startDateASN1"],      file=fout)
        print(params["endDateASN1"],        file=fout)
        print(int(params["x509v3"]),        file=fout)
        print(sbj["country"],               file=fout)
        print(sbj["state"],                 file=fout)
        print(sbj["locality"],              file=fout)
        print(sbj["organization"],          file=fout)
        print(sbj["organization_unit_name"],file=fout)
        print(sbj["common_name"],           file=fout)
        print(sbj["email"],                 file=fout)
        print(params["engine_path"],        file=fout)
        print(params["pubkey_path"],        file=fout) # the public key implicitly tells what curve is used
        print(params["output_cert_path"],   file=fout)
        print(int(params["load_ecengine"]),   file=fout)
        print(int(params["debug"]),         file=fout)

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
    root_cert_parameters, runtime_variables = load_json(argv[1]), load_json(argv[2])
    if (not root_cert_parameters) or (not runtime_variables):
        return 1

    obj = dict(root_cert_parameters)
    obj.update(runtime_variables) # we override the root_cert_parameters if the runtime forces so (especially for x509 v3 flag)
    try:
        dump_c_parameters(obj)
    except IOError as e:
        print("ERROR: could not write out c parameters file ", OUTPUT_FILE_PATH, file=sys.stderr)
        return 1
    print ("INFO: Conversion is done!")
    return 0

exit(main(sys.argv))
