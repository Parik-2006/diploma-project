from django.shortcuts import render
from django.http import HttpResponseRedirect
# Create your views here.
from django.contrib.auth.models import User,auth 
from django.contrib import messages
from .models import MaliciousBot

def index(request):
    return render(request,"index.html")


def register(request):
    if request.method=="POST":
        first=request.POST['fname']
        last=request.POST['lname']
        uname=request.POST['uname']
        em=request.POST['email']
        ps=request.POST['psw']
        ps1=request.POST['psw1']
        if ps==ps1:
            if User.objects.filter(username=uname).exists():
                messages.info(request,"Username Exists")
                return render(request,"register.html")
            elif User.objects.filter(email=em).exists():
                messages.info(request,"Email exists")
                return render(request,"register.html")
            else:
                user=User.objects.create_user(first_name=first,
            last_name=last,username=uname,email=em,password=ps)
                user.save()
                return HttpResponseRedirect("login")
        else:
            messages.info(request,"Password not Matching")
            return render(request,"register.html")

    return render(request,"register.html")

def login(request):
    if request.method=="POST":
        uname=request.POST['uname']
        ps=request.POST['psw']
        user=auth.authenticate(username=uname,password=ps)
        if user is not None:
            auth.login(request,user)
            return HttpResponseRedirect('data')
        else:
            messages.info(request,"Invalid Credentials")
            return render(request,"login.html")
    return render(request,"login.html")



def adminlogin(request):
    if request.method=="POST":
        un=request.POST['uname']
        ps=request.POST['psw']
        user=auth.authenticate(username=un,password=ps)
        if user is not None and user.is_superuser:
            auth.login(request,user)
            return HttpResponseRedirect('adminhome')
        else:
            messages.info(request,"Invalid Credentials")
            return render(request,"adminlogin.html")
    return render(request,"adminlogin.html")


def logout(request):
    auth.logout(request)
    return HttpResponseRedirect('/')


def data(request):
    if request.method=="POST":
        url1=request.POST['bot']
        import re
        import string
        import logging

        import numpy as np
        import pandas as pd
        import seaborn as sns
        import matplotlib.pyplot as plt

        from urllib.parse import urlparse
        from sklearn.model_selection import train_test_split, cross_val_score, cross_val_predict
        from sklearn.metrics import accuracy_score, recall_score, precision_score, f1_score, classification_report, confusion_matrix
        from sklearn.tree import DecisionTreeClassifier
        from sklearn.ensemble import RandomForestClassifier, AdaBoostClassifier, ExtraTreesClassifier, GradientBoostingClassifier, BaggingClassifier
        from sklearn.neighbors import KNeighborsClassifier
        from sklearn.linear_model import SGDClassifier, LogisticRegression, RidgeClassifier, Perceptron
        from sklearn.naive_bayes import GaussianNB, MultinomialNB
        from sklearn.svm import SVC
        from sklearn.neural_network import MLPClassifier
        from sklearn.gaussian_process import GaussianProcessClassifier
        from sklearn.mixture import GaussianMixture
        from sklearn.cluster import KMeans
        from sklearn.pipeline import Pipeline
        from sklearn.discriminant_analysis import LinearDiscriminantAnalysis, QuadraticDiscriminantAnalysis
        from xgboost import XGBClassifier
        #tgbm import LGBMClassifier
        #from catboost import CatBoostClassifier

        from tldextract import extract as tld_extract
        from tld import get_tld, is_tld
        from tld.exceptions import TldDomainNotFound, TldBadUrl, TldIOError

        from colorama import Fore
        from datetime import datetime
        from plotly.subplots import make_subplots
        from plotly import graph_objects as go
        from wordcloud import WordCloud
        from gensim.models import Word2Vec
        import tldextract
        import hashlib
        import whois
        import warnings

        #warnings.filterwarnings("ignore")
        urls_data = pd.read_csv(r'static/dataset/Phishing.csv')
        print(urls_data.head())
        print(urls_data.info())
        print(urls_data.isnull().sum())
        count = urls_data['type'].value_counts()
        colors = [
            '#FF6633', '#FFB399', '#FF33FF', '#FFFF99', '#00B3E6',
            '#E6B333', '#3366E6', '#999966', '#99FF99', '#B34D4D'
        ]
        fig = go.Figure(data=[go.Bar(x=count.index, y=count, marker=dict(color=colors))])
        fig.update_layout(
            xaxis_title='Types',
            yaxis_title='Count',
            title='Count of Different Types of URLs',
            plot_bgcolor='black',
            paper_bgcolor='black',
            font=dict(color='white')
        )
        fig.update_xaxes(tickfont=dict(color='white'))
        fig.update_yaxes(tickfont=dict(color='white'))
        fig.show()
        urls_data["url_type"] = urls_data["type"].replace({
    'benign':0,
    'defacement':1,
    'phishing':2,
    'malware':3
});
        def get_url_length(url):
            # Remove common prefixes
            prefixes = ['http://', 'https://']
            for prefix in prefixes:
                if url.startswith(prefix):
                    url = url[len(prefix):]

            # Remove 'www.' if present
            url = url.replace('www.', '')

            # Return the length of the remaining URL
            return len(url)
        urls_data['url_len'] = urls_data['url'].apply(lambda x: get_url_length(str(x)))
        def extract_pri_domain(url):
            try:
                res = get_tld(url, as_object = True, fail_silently=False,fix_protocol=True)
                pri_domain= res.parsed_url.netloc
            except :
                pri_domain= None
            return pri_domain
        urls_data['pri_domain'] = urls_data['url'].apply(lambda x: extract_pri_domain(x))
        def count_letters(url):
            num_letters = sum(char.isalpha() for char in url)
            return num_letters

        def count_digits(url):
            num_digits = sum(char.isdigit() for char in url)
            return num_digits

        def count_special_chars(url):
            special_chars = set(string.punctuation)
            num_special_chars = sum(char in special_chars for char in url)
            return num_special_chars
        urls_data['letters_count']        = urls_data['url'].apply(lambda x: count_letters(x))
        urls_data['digits_count']         = urls_data['url'].apply(lambda x: count_digits(x))
        urls_data['special_chars_count']  = urls_data['url'].apply(lambda x: count_special_chars(x))
        def has_shortening_service(url):
            pattern = re.compile(r'https?://(?:www\.)?(?:\w+\.)*(\w+)\.\w+')
            match = pattern.search(url)
            
            if match:
                domain = match.group(1)
                common_shortening_services = ['bit', 'goo', 'tinyurl', 'ow', 't', 'is',
                                            'cli', 'yfrog', 'migre', 'ff', 'url4', 'twit',
                                            'su', 'snipurl', 'short', 'BudURL', 'ping', 
                                            'post', 'Just', 'bkite', 'snipr', 'fic', 
                                            'loopt', 'doiop', 'short', 'kl', 'wp', 
                                            'rubyurl', 'om', 'to', 'bit', 't', 'lnkd', 
                                            'db', 'qr', 'adf', 'goo', 'bitly', 'cur', 
                                            'tinyurl', 'ow', 'bit', 'ity', 'q', 'is', 
                                            'po', 'bc', 'twitthis', 'u', 'j', 'buzurl', 
                                            'cutt', 'u', 'yourls', 'x', 'prettylinkpro', 
                                            'scrnch', 'filoops', 'vzturl', 'qr', '1url', 
                                            'tweez', 'v', 'tr', 'link', 'zip']
                
                if domain.lower() in common_shortening_services:
                    return 1
            return 0
        urls_data['shortened']  = urls_data['url'].apply(lambda x: has_shortening_service(x))
        def abnormal_url(url):
            parsed_url = urlparse(url)
            netloc = parsed_url.netloc
            if netloc:
                netloc = str(netloc)
                match = re.search(netloc, url)
                if match:
                    return 1
            return 0
        urls_data['abnormal_url']  = urls_data['url'].apply(lambda x: abnormal_url(x))
        def secure_http(url):
            return int(urlparse(url).scheme == 'https')
        urls_data['secure_http']  = urls_data['url'].apply(lambda x: secure_http(x))
        import ipaddress
        def have_ip_address(url):
            try:
                parsed_url = urlparse(url)
                if parsed_url.hostname:
                    ip = ipaddress.ip_address(parsed_url.hostname)
                    return isinstance(ip, (ipaddress.IPv4Address, ipaddress.IPv6Address))
            except ValueError:
                pass  # Invalid hostname or IP address

            return 0
        urls_data['have_ip']  = urls_data['url'].apply(lambda x: have_ip_address(x))
        urls_data.fillna(0,inplace=True)
        def get_url_region(primary_domain):
            ccTLD_to_region = {
            ".ac": "Ascension Island",
            ".ad": "Andorra",
            ".ae": "United Arab Emirates",
            ".af": "Afghanistan",
            ".ag": "Antigua and Barbuda",
            ".ai": "Anguilla",
            ".al": "Albania",
            ".am": "Armenia",
            ".an": "Netherlands Antilles",
            ".ao": "Angola",
            ".aq": "Antarctica",
            ".ar": "Argentina",
            ".as": "American Samoa",
            ".at": "Austria",
            ".au": "Australia",
            ".aw": "Aruba",
            ".ax": "Åland Islands",
            ".az": "Azerbaijan",
            ".ba": "Bosnia and Herzegovina",
            ".bb": "Barbados",
            ".bd": "Bangladesh",
            ".be": "Belgium",
            ".bf": "Burkina Faso",
            ".bg": "Bulgaria",
            ".bh": "Bahrain",
            ".bi": "Burundi",
            ".bj": "Benin",
            ".bm": "Bermuda",
            ".bn": "Brunei Darussalam",
            ".bo": "Bolivia",
            ".br": "Brazil",
            ".bs": "Bahamas",
            ".bt": "Bhutan",
            ".bv": "Bouvet Island",
            ".bw": "Botswana",
            ".by": "Belarus",
            ".bz": "Belize",
            ".ca": "Canada",
            ".cc": "Cocos Islands",
            ".cd": "Democratic Republic of the Congo",
            ".cf": "Central African Republic",
            ".cg": "Republic of the Congo",
            ".ch": "Switzerland",
            ".ci": "Côte d'Ivoire",
            ".ck": "Cook Islands",
            ".cl": "Chile",
            ".cm": "Cameroon",
            ".cn": "China",
            ".co": "Colombia",
            ".cr": "Costa Rica",
            ".cu": "Cuba",
            ".cv": "Cape Verde",
            ".cw": "Curaçao",
            ".cx": "Christmas Island",
            ".cy": "Cyprus",
            ".cz": "Czech Republic",
            ".de": "Germany",
            ".dj": "Djibouti",
            ".dk": "Denmark",
            ".dm": "Dominica",
            ".do": "Dominican Republic",
            ".dz": "Algeria",
            ".ec": "Ecuador",
            ".ee": "Estonia",
            ".eg": "Egypt",
            ".er": "Eritrea",
            ".es": "Spain",
            ".et": "Ethiopia",
            ".eu": "European Union",
            ".fi": "Finland",
            ".fj": "Fiji",
            ".fk": "Falkland Islands",
            ".fm": "Federated States of Micronesia",
            ".fo": "Faroe Islands",
            ".fr": "France",
            ".ga": "Gabon",
            ".gb": "United Kingdom",
            ".gd": "Grenada",
            ".ge": "Georgia",
            ".gf": "French Guiana",
            ".gg": "Guernsey",
            ".gh": "Ghana",
            ".gi": "Gibraltar",
            ".gl": "Greenland",
            ".gm": "Gambia",
            ".gn": "Guinea",
            ".gp": "Guadeloupe",
            ".gq": "Equatorial Guinea",
            ".gr": "Greece",
            ".gs": "South Georgia and the South Sandwich Islands",
            ".gt": "Guatemala",
            ".gu": "Guam",
            ".gw": "Guinea-Bissau",
            ".gy": "Guyana",
            ".hk": "Hong Kong",
            ".hm": "Heard Island and McDonald Islands",
            ".hn": "Honduras",
            ".hr": "Croatia",
            ".ht": "Haiti",
            ".hu": "Hungary",
            ".id": "Indonesia",
            ".ie": "Ireland",
            ".il": "Israel",
            ".im": "Isle of Man",
            ".in": "India",
            ".io": "British Indian Ocean Territory",
            ".iq": "Iraq",
            ".ir": "Iran",
            ".is": "Iceland",
            ".it": "Italy",
            ".je": "Jersey",
            ".jm": "Jamaica",
            ".jo": "Jordan",
            ".jp": "Japan",
            ".ke": "Kenya",
            ".kg": "Kyrgyzstan",
            ".kh": "Cambodia",
            ".ki": "Kiribati",
            ".km": "Comoros",
            ".kn": "Saint Kitts and Nevis",
            ".kp": "Democratic People's Republic of Korea (North Korea)",
            ".kr": "Republic of Korea (South Korea)",
            ".kw": "Kuwait",
            ".ky": "Cayman Islands",
            ".kz": "Kazakhstan",
            ".la": "Laos",
            ".lb": "Lebanon",
            ".lc": "Saint Lucia",
            ".li": "Liechtenstein",
            ".lk": "Sri Lanka",
            ".lr": "Liberia",
            ".ls": "Lesotho",
            ".lt": "Lithuania",
            ".lu": "Luxembourg",
            ".lv": "Latvia",
            ".ly": "Libya",
            ".ma": "Morocco",
            ".mc": "Monaco",
            ".md": "Moldova",
            ".me": "Montenegro",
            ".mf": "Saint Martin (French part)",
            ".mg": "Madagascar",
            ".mh": "Marshall Islands",
            ".mk": "North Macedonia",
            ".ml": "Mali",
            ".mm": "Myanmar",
            ".mn": "Mongolia",
            ".mo": "Macao",
            ".mp": "Northern Mariana Islands",
            ".mq": "Martinique",
            ".mr": "Mauritania",
            ".ms": "Montserrat",
            ".mt": "Malta",
            ".mu": "Mauritius",
            ".mv": "Maldives",
            ".mw": "Malawi",
            ".mx": "Mexico",
            ".my": "Malaysia",
            ".mz": "Mozambique",
            ".na": "Namibia",
            ".nc": "New Caledonia",
            ".ne": "Niger",
            ".nf": "Norfolk Island",
            ".ng": "Nigeria",
            ".ni": "Nicaragua",
            ".nl": "Netherlands",
            ".no": "Norway",
            ".np": "Nepal",
            ".nr": "Nauru",
            ".nu": "Niue",
            ".nz": "New Zealand",
            ".om": "Oman",
            ".pa": "Panama",
            ".pe": "Peru",
            ".pf": "French Polynesia",
            ".pg": "Papua New Guinea",
            ".ph": "Philippines",
            ".pk": "Pakistan",
            ".pl": "Poland",
            ".pm": "Saint Pierre and Miquelon",
            ".pn": "Pitcairn",
            ".pr": "Puerto Rico",
            ".ps": "Palestinian Territory",
            ".pt": "Portugal",
            ".pw": "Palau",
            ".py": "Paraguay",
            ".qa": "Qatar",
            ".re": "Réunion",
            ".ro": "Romania",
            ".rs": "Serbia",
            ".ru": "Russia",
            ".rw": "Rwanda",
            ".sa": "Saudi Arabia",
            ".sb": "Solomon Islands",
            ".sc": "Seychelles",
            ".sd": "Sudan",
            ".se": "Sweden",
            ".sg": "Singapore",
            ".sh": "Saint Helena",
            ".si": "Slovenia",
            ".sj": "Svalbard and Jan Mayen",
            ".sk": "Slovakia",
            ".sl": "Sierra Leone",
            ".sm": "San Marino",
            ".sn": "Senegal",
            ".so": "Somalia",
            ".sr": "Suriname",
            ".ss": "South Sudan",
            ".st": "São Tomé and Príncipe",
            ".sv": "El Salvador",
            ".sx": "Sint Maarten (Dutch part)",
            ".sy": "Syria",
            ".sz": "Eswatini",
            ".tc": "Turks and Caicos Islands",
            ".td": "Chad",
            ".tf": "French Southern Territories",
            ".tg": "Togo",
            ".th": "Thailand",
            ".tj": "Tajikistan",
            ".tk": "Tokelau",
            ".tl": "Timor-Leste",
            ".tm": "Turkmenistan",
            ".tn": "Tunisia",
            ".to": "Tonga",
            ".tr": "Turkey",
            ".tt": "Trinidad and Tobago",
            ".tv": "Tuvalu",
            ".tw": "Taiwan",
            ".tz": "Tanzania",
            ".ua": "Ukraine",
            ".ug": "Uganda",
            ".uk": "United Kingdom",
            ".us": "United States",
            ".uy": "Uruguay",
            ".uz": "Uzbekistan",
            ".va": "Vatican City",
            ".vc": "Saint Vincent and the Grenadines",
            ".ve": "Venezuela",
            ".vg": "British Virgin Islands",
            ".vi": "U.S. Virgin Islands",
            ".vn": "Vietnam",
            ".vu": "Vanuatu",
            ".wf": "Wallis and Futuna",
            ".ws": "Samoa",
            ".ye": "Yemen",
            ".yt": "Mayotte",
            ".za": "South Africa",
            ".zm": "Zambia",
            ".zw": "Zimbabwe"
            }
            
            for ccTLD in ccTLD_to_region:
                if primary_domain.endswith(ccTLD):
                    return ccTLD_to_region[ccTLD]
            
            return "Global"
        urls_data['url_region'] = urls_data['pri_domain'].apply(lambda x: get_url_region(str(x)))
        def extract_root_domain(url):
            extracted = tldextract.extract(url)
            root_domain = extracted.domain
            return root_domain
        urls_data['root_domain'] = urls_data['pri_domain'].apply(lambda x: extract_root_domain(str(x)))
        urls_data.drop_duplicates(inplace=True)
        data = urls_data.drop(columns=['url','type','pri_domain'])
        print(data.head())
        data = data[data['root_domain'] != '0']
        def hash_encode(category):
            hash_object = hashlib.md5(category.encode())
            return int(hash_object.hexdigest(), 16) % (10 ** 8)
        data['root_domain'] = data['root_domain'].apply(hash_encode)
        data['url_region'] = data['url_region'].apply(hash_encode)  
        x = data.drop(columns=['url_type'])
        # Ensure classifier target contains only valid discrete labels.
        y = pd.to_numeric(data['url_type'], errors='coerce')
        valid_mask = y.notna()
        x = x.loc[valid_mask]
        y = y.loc[valid_mask].astype(int)
        x_train,x_test,y_train,y_test = train_test_split(x,y,test_size=0.3, random_state=42)
        classifiers = [
    DecisionTreeClassifier(),
    RandomForestClassifier(),
    AdaBoostClassifier(),
    KNeighborsClassifier(),
    ExtraTreesClassifier(),
    GaussianNB()
]
        results = []
        for classifier in classifiers:
            pipeline = Pipeline([
                ('classifier', classifier)
            ])
            scores = cross_val_score(pipeline, x, y, cv=2, scoring='accuracy')
            y_pred = cross_val_predict(pipeline, x, y, cv=2)
            accuracy = accuracy_score(y, y_pred)
            recall = recall_score(y, y_pred, average='weighted')
            precision = precision_score(y, y_pred, average='weighted', zero_division=1) 
            f1 = f1_score(y, y_pred, average='weighted')
            results.append((classifier.__class__.__name__, accuracy, recall, precision, f1))
        results = pd.DataFrame(results, columns=['Classifier', 'Accuracy', 'Recall', 'Precision', 'F1-Score'])
        results = results.sort_values(by='Accuracy', ascending=False)
        print(results.head())
        pipeline = Pipeline([
        ('classifier', ExtraTreesClassifier())
    ])
        pipeline.fit(x_train,y_train)
        y_pred = pipeline.predict(x_test)
        print(classification_report(y_test,y_pred))
        def get_numerical_values(url):
            url = url.replace('www.', '')
            url_len = get_url_length(url)
            letters_count = count_letters(url)
            digits_count  = count_digits(url)
            special_chars_count = count_special_chars(url)
            shortened = has_shortening_service(url)
            abnormal = abnormal_url(url)
            secure_https = secure_http(url)
            have_ip = have_ip_address(url)
            
            parsed_url  = urlparse(url)
            root_domain = parsed_url.netloc.split(".")[0]
            url_region = get_url_region(root_domain)
            
            return {
                'url_len': url_len,
                'letters_count': letters_count,
                'digits_count': digits_count,
                'special_chars_count': special_chars_count,
                'shortened': shortened,
                'abnormal': abnormal,
                'secure_http': secure_https,
                'have_ip': have_ip,
                'url_region': hash_encode(url_region),
                'root_domain': hash_encode(root_domain)
            }

        def get_url_length(url):
            return len(url)
        def extract_pri_domain(url):
            try:
                res = get_tld(url, as_object = True, fail_silently=False,fix_protocol=True)
                pri_domain= res.parsed_url.netloc
            except :
                pri_domain= None
            return pri_domain
        def count_letters(url):
            num_letters = sum(char.isalpha() for char in url)
            return num_letters

        def count_digits(url):
            num_digits = sum(char.isdigit() for char in url)
            return num_digits
        def count_special_chars(url):
            special_chars = "!@#$%^&*()_+-=[]{};:,.<>/?`~|"
            num_special_chars = sum(char in special_chars for char in url)
            return num_special_chars
        def has_shortening_service(url):
            pattern = re.compile(r'bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                                r'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                                r'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                                r'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                                r'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                                r'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                                r'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|'
                                r'tr\.im|link\.zip\.net')
            match = pattern.search(url)
            return int(bool(match))
        def abnormal_url(url):
            parsed_url = urlparse(url)
            hostname = parsed_url.hostname
            if hostname:
                hostname = str(hostname)
                match = re.search(hostname, url)
                if match:
                    return 1
            return 0
        def secure_http(url):
            scheme = urlparse(url).scheme
            if scheme == 'https':
                return 1
            else:
                return 0
        def have_ip_address(url):
            pattern = r'(([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.' \
                    r'([01]?\d\d?|2[0-4]\d|25[0-5])\/)|' \
                    r'(([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.' \
                    r'([01]?\d\d?|2[0-4]\d|25[0-5])\/)|' \
                    r'((0x[0-9a-fA-F]{1,2})\.(0x[0-9a-fA-F]{1,2})\.(0x[0-9a-fA-F]{1,2})\.(0x[0-9a-fA-F]{1,2})\/)' \
                    r'(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}|' \
                    r'([0-9]+(?:\.[0-9]+){3}:[0-9]+)|' \
                    r'((?:(?:\d|[01]?\d\d|2[0-4]\d|25[0-5])\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d|\d)(?:\/\d{1,2})?)'

            match = re.search(pattern, url)
            if match:
                return 1
            else:
                return 0
        def get_url_region(primary_domain):
            ccTLD_to_region = {
            ".ac": "Ascension Island",
            ".ad": "Andorra",
            ".ae": "United Arab Emirates",
            ".af": "Afghanistan",
            ".ag": "Antigua and Barbuda",
            ".ai": "Anguilla",
            ".al": "Albania",
            ".am": "Armenia",
            ".an": "Netherlands Antilles",
            ".ao": "Angola",
            ".aq": "Antarctica",
            ".ar": "Argentina",
            ".as": "American Samoa",
            ".at": "Austria",
            ".au": "Australia",
            ".aw": "Aruba",
            ".ax": "Åland Islands",
            ".az": "Azerbaijan",
            ".ba": "Bosnia and Herzegovina",
            ".bb": "Barbados",
            ".bd": "Bangladesh",
            ".be": "Belgium",
            ".bf": "Burkina Faso",
            ".bg": "Bulgaria",
            ".bh": "Bahrain",
            ".bi": "Burundi",
            ".bj": "Benin",
            ".bm": "Bermuda",
            ".bn": "Brunei Darussalam",
            ".bo": "Bolivia",
            ".br": "Brazil",
            ".bs": "Bahamas",
            ".bt": "Bhutan",
            ".bv": "Bouvet Island",
            ".bw": "Botswana",
            ".by": "Belarus",
            ".bz": "Belize",
            ".ca": "Canada",
            ".cc": "Cocos Islands",
            ".cd": "Democratic Republic of the Congo",
            ".cf": "Central African Republic",
            ".cg": "Republic of the Congo",
            ".ch": "Switzerland",
            ".ci": "Côte d'Ivoire",
            ".ck": "Cook Islands",
            ".cl": "Chile",
            ".cm": "Cameroon",
            ".cn": "China",
            ".co": "Colombia",
            ".cr": "Costa Rica",
            ".cu": "Cuba",
            ".cv": "Cape Verde",
            ".cw": "Curaçao",
            ".cx": "Christmas Island",
            ".cy": "Cyprus",
            ".cz": "Czech Republic",
            ".de": "Germany",
            ".dj": "Djibouti",
            ".dk": "Denmark",
            ".dm": "Dominica",
            ".do": "Dominican Republic",
            ".dz": "Algeria",
            ".ec": "Ecuador",
            ".ee": "Estonia",
            ".eg": "Egypt",
            ".er": "Eritrea",
            ".es": "Spain",
            ".et": "Ethiopia",
            ".eu": "European Union",
            ".fi": "Finland",
            ".fj": "Fiji",
            ".fk": "Falkland Islands",
            ".fm": "Federated States of Micronesia",
            ".fo": "Faroe Islands",
            ".fr": "France",
            ".ga": "Gabon",
            ".gb": "United Kingdom",
            ".gd": "Grenada",
            ".ge": "Georgia",
            ".gf": "French Guiana",
            ".gg": "Guernsey",
            ".gh": "Ghana",
            ".gi": "Gibraltar",
            ".gl": "Greenland",
            ".gm": "Gambia",
            ".gn": "Guinea",
            ".gp": "Guadeloupe",
            ".gq": "Equatorial Guinea",
            ".gr": "Greece",
            ".gs": "South Georgia and the South Sandwich Islands",
            ".gt": "Guatemala",
            ".gu": "Guam",
            ".gw": "Guinea-Bissau",
            ".gy": "Guyana",
            ".hk": "Hong Kong",
            ".hm": "Heard Island and McDonald Islands",
            ".hn": "Honduras",
            ".hr": "Croatia",
            ".ht": "Haiti",
            ".hu": "Hungary",
            ".id": "Indonesia",
            ".ie": "Ireland",
            ".il": "Israel",
            ".im": "Isle of Man",
            ".in": "India",
            ".io": "British Indian Ocean Territory",
            ".iq": "Iraq",
            ".ir": "Iran",
            ".is": "Iceland",
            ".it": "Italy",
            ".je": "Jersey",
            ".jm": "Jamaica",
            ".jo": "Jordan",
            ".jp": "Japan",
            ".ke": "Kenya",
            ".kg": "Kyrgyzstan",
            ".kh": "Cambodia",
            ".ki": "Kiribati",
            ".km": "Comoros",
            ".kn": "Saint Kitts and Nevis",
            ".kp": "Democratic People's Republic of Korea (North Korea)",
            ".kr": "Republic of Korea (South Korea)",
            ".kw": "Kuwait",
            ".ky": "Cayman Islands",
            ".kz": "Kazakhstan",
            ".la": "Laos",
            ".lb": "Lebanon",
            ".lc": "Saint Lucia",
            ".li": "Liechtenstein",
            ".lk": "Sri Lanka",
            ".lr": "Liberia",
            ".ls": "Lesotho",
            ".lt": "Lithuania",
            ".lu": "Luxembourg",
            ".lv": "Latvia",
            ".ly": "Libya",
            ".ma": "Morocco",
            ".mc": "Monaco",
            ".md": "Moldova",
            ".me": "Montenegro",
            ".mf": "Saint Martin (French part)",
            ".mg": "Madagascar",
            ".mh": "Marshall Islands",
            ".mk": "North Macedonia",
            ".ml": "Mali",
            ".mm": "Myanmar",
            ".mn": "Mongolia",
            ".mo": "Macao",
            ".mp": "Northern Mariana Islands",
            ".mq": "Martinique",
            ".mr": "Mauritania",
            ".ms": "Montserrat",
            ".mt": "Malta",
            ".mu": "Mauritius",
            ".mv": "Maldives",
            ".mw": "Malawi",
            ".mx": "Mexico",
            ".my": "Malaysia",
            ".mz": "Mozambique",
            ".na": "Namibia",
            ".nc": "New Caledonia",
            ".ne": "Niger",
            ".nf": "Norfolk Island",
            ".ng": "Nigeria",
            ".ni": "Nicaragua",
            ".nl": "Netherlands",
            ".no": "Norway",
            ".np": "Nepal",
            ".nr": "Nauru",
            ".nu": "Niue",
            ".nz": "New Zealand",
            ".om": "Oman",
            ".pa": "Panama",
            ".pe": "Peru",
            ".pf": "French Polynesia",
            ".pg": "Papua New Guinea",
            ".ph": "Philippines",
            ".pk": "Pakistan",
            ".pl": "Poland",
            ".pm": "Saint Pierre and Miquelon",
            ".pn": "Pitcairn",
            ".pr": "Puerto Rico",
            ".ps": "Palestinian Territory",
            ".pt": "Portugal",
            ".pw": "Palau",
            ".py": "Paraguay",
            ".qa": "Qatar",
            ".re": "Réunion",
            ".ro": "Romania",
            ".rs": "Serbia",
            ".ru": "Russia",
            ".rw": "Rwanda",
            ".sa": "Saudi Arabia",
            ".sb": "Solomon Islands",
            ".sc": "Seychelles",
            ".sd": "Sudan",
            ".se": "Sweden",
            ".sg": "Singapore",
            ".sh": "Saint Helena",
            ".si": "Slovenia",
            ".sj": "Svalbard and Jan Mayen",
            ".sk": "Slovakia",
            ".sl": "Sierra Leone",
            ".sm": "San Marino",
            ".sn": "Senegal",
            ".so": "Somalia",
            ".sr": "Suriname",
            ".ss": "South Sudan",
            ".st": "São Tomé and Príncipe",
            ".sv": "El Salvador",
            ".sx": "Sint Maarten (Dutch part)",
            ".sy": "Syria",
            ".sz": "Eswatini",
            ".tc": "Turks and Caicos Islands",
            ".td": "Chad",
            ".tf": "French Southern Territories",
            ".tg": "Togo",
            ".th": "Thailand",
            ".tj": "Tajikistan",
            ".tk": "Tokelau",
            ".tl": "Timor-Leste",
            ".tm": "Turkmenistan",
            ".tn": "Tunisia",
            ".to": "Tonga",
            ".tr": "Turkey",
            ".tt": "Trinidad and Tobago",
            ".tv": "Tuvalu",
            ".tw": "Taiwan",
            ".tz": "Tanzania",
            ".ua": "Ukraine",
            ".ug": "Uganda",
            ".uk": "United Kingdom",
            ".us": "United States",
            ".uy": "Uruguay",
            ".uz": "Uzbekistan",
            ".va": "Vatican City",
            ".vc": "Saint Vincent and the Grenadines",
            ".ve": "Venezuela",
            ".vg": "British Virgin Islands",
            ".vi": "U.S. Virgin Islands",
            ".vn": "Vietnam",
            ".vu": "Vanuatu",
            ".wf": "Wallis and Futuna",
            ".ws": "Samoa",
            ".ye": "Yemen",
            ".yt": "Mayotte",
            ".za": "South Africa",
            ".zm": "Zambia",
            ".zw": "Zimbabwe"
            }
            
            for ccTLD in ccTLD_to_region:
                if primary_domain.endswith(ccTLD):
                    return ccTLD_to_region[ccTLD]
            
            return "Global"
        def extract_root_domain(url):
            extracted = tldextract.extract(url)
            root_domain = extracted.domain
            return root_domain
        def hash_encode(category):
            hash_object = hashlib.md5(category.encode())
            return int(hash_object.hexdigest(), 16) % (10 ** 8)
        def model_predict(url):
            class_mapping = {
                0: 'benign',
                1: 'defacement',
                2: 'phishing',
                3: 'malware'
            }
            numerical_values = get_numerical_values(url)
            prediction_int = pipeline.predict(np.array(list(numerical_values.values())).reshape(1, -1))[0]
            prediction_label = class_mapping.get(prediction_int, 'Unknown')
            return prediction_int, prediction_label
        url = "https://www.example.com"
        numerical_values = get_numerical_values(url)
        print(numerical_values)
        print(len(numerical_values))
        print(list(numerical_values.values()))
        print(model_predict(url)[0],model_predict(url)[1])
        
        numerical_values = get_numerical_values(url1)
        print(numerical_values)
        print(len(numerical_values))
        print(list(numerical_values.values()))
        print(model_predict(url)[0],model_predict(url1)[1])
        from .models import MaliciousBot
        m=MaliciousBot.objects.create(url=url1,bot=model_predict(url1)[1])
        m.save()
        return render(request,"predict.html",{"prediction":model_predict(url)[0],"pred":model_predict(url1)[1]})

    return render(request,"data.html")

def predict(request):
    return render(request,"predict.html")


def adminhome(request):
    mb=MaliciousBot.objects.all()
    return render(request,"adminhome.html",{"mb":mb})
