# Values read from the app's results table on Samsung Galaxy A55 (SM-A556E), Android 16, 140 chars, 50 iterations; 3 runs
runs = {
 "RSA-512":   [(5.00,.332,.513),(4.97,.426,.604),(6.07,.420,.585)],
 "RSA-1024":  [(12.6,.120,.411),(15.0,.117,.407),(13.7,.129,.416)],
 "RSA-2048":  [(87.3,.122,1.11),(91.6,.109,1.09),(86.2,.138,1.13)],
 "RSA-3072":  [(517,.223,3.09),(373,.218,3.10),(410,.222,3.11)],
 "RSA-4096":  [(1882,.322,6.71),(363,.313,6.70),(805,.326,6.72)],
 "ECC P-224": [(.165,.588,3.90),(.165,.564,4.03),(.155,.635,3.84)],
 "ECC P-256": [(.069,.358,.333),(.070,.348,.319),(.067,.365,.334)],
 "ECC P-384": [(.556,1.38,.896),(.496,1.37,.861),(.515,1.35,.869)],
 "ECC P-521": [(1.27,3.25,1.97),(1.32,3.19,1.93),(1.36,3.26,1.97)],
}
sms = {"RSA-512":"603 / 4","RSA-1024":"347 / 3","RSA-2048":"347 / 3","RSA-3072":"515 / 4","RSA-4096":"687 / 5",
       "ECC P-224":"255 / 2","ECC P-256":"259 / 2","ECC P-384":"283 / 2","ECC P-521":"307 / 3"}
import json
out={}
for k,v in runs.items():
    kg=[x[0] for x in v]; en=[x[1] for x in v]; de=[x[2] for x in v]
    out[k]={"kg":sum(kg)/3,"kgmin":min(kg),"kgmax":max(kg),"enc":sum(en)/3,"encmin":min(en),"encmax":max(en),"dec":sum(de)/3,"decmin":min(de),"decmax":max(de),"sms":sms[k]}
json.dump(out,open("phone.json","w"),indent=1)
for k,o in out.items(): print(f"{k:10} kg {o['kg']:8.3f} [{o['kgmin']}-{o['kgmax']}]  enc {o['enc']:.3f}  dec {o['dec']:.3f}")
p=out
print("dec RSA3072/P256", p["RSA-3072"]["dec"]/p["ECC P-256"]["dec"])
print("dec RSA2048/P224", p["RSA-2048"]["dec"]/p["ECC P-224"]["dec"])
print("enc P256/RSA3072", p["ECC P-256"]["enc"]/p["RSA-3072"]["enc"])
print("kg RSA3072/P256", p["RSA-3072"]["kg"]/p["ECC P-256"]["kg"])
print("dec RSA4096/P384", p["RSA-4096"]["dec"]/p["ECC P-384"]["dec"])
