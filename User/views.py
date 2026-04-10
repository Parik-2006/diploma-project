from django.shortcuts import render
from django.http import HttpResponseRedirect
# Create your views here.
from django.contrib.auth.models import User,auth
from django.contrib import messages
from .models import MaliciousBot

# Always import these basic modules
import re
import string
import hashlib
from urllib.parse import urlparse

# ML imports - made optional for local development
try:
    import numpy as np
    import pandas as pd
    from sklearn.model_selection import train_test_split
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import Pipeline
    import ipaddress
    ML_AVAILABLE = True
except ImportError as e:
    print(f"ML dependencies not available: {e}")
    print("Running in local mode without ML features")
    ML_AVAILABLE = False

# Try to import tldextract, but have a fallback
try:
    from tldextract import extract as tld_extract
    TLDEXTRACT_AVAILABLE = True
except ImportError:
    print("Warning: tldextract not available, using fallback domain extraction")
    TLDEXTRACT_AVAILABLE = False

# Global pipeline variable
pipeline = None
model_trained = False

# Define helper functions
def hash_encode(category):
    hash_object = hashlib.md5(str(category).encode())
    return int(hash_object.hexdigest(), 16) % (10 ** 8)

def extract_root_domain(url):
    """Extract root domain from URL with fallback method"""
    try:
        if TLDEXTRACT_AVAILABLE:
            extracted = tld_extract(url)
            root_domain = extracted.domain
            return root_domain
        else:
            # Fallback: simple extraction
            from urllib.parse import urlparse
            parsed = urlparse(url)
            domain = parsed.netloc or parsed.path
            # Remove 'www.' prefix if present
            if domain.startswith('www.'):
                domain = domain[4:]
            # Get the main domain part
            parts = domain.split('.')
            if len(parts) >= 2:
                return parts[-2]
            return domain
    except Exception as e:
        print(f"Error extracting root domain from {url}: {e}")
        return "unknown"

# Define feature extraction functions if ML is available
if ML_AVAILABLE:
    def get_url_length(url):
        prefixes = ['http://', 'https://']
        for prefix in prefixes:
            if url.startswith(prefix):
                url = url[len(prefix):]
        url = url.replace('www.', '')
        return len(url)

    def count_letters(url):
        return sum(char.isalpha() for char in url)

    def count_digits(url):
        return sum(char.isdigit() for char in url)

    def count_special_chars(url):
        special_chars = set(string.punctuation)
        return sum(char in special_chars for char in url)

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
            ".ac": "Ascension Island", ".ad": "Andorra", ".ae": "United Arab Emirates", ".af": "Afghanistan",
            ".ag": "Antigua and Barbuda", ".ai": "Anguilla", ".al": "Albania", ".am": "Armenia",
            ".an": "Netherlands Antilles", ".ao": "Angola", ".aq": "Antarctica", ".ar": "Argentina",
            ".as": "American Samoa", ".at": "Austria", ".au": "Australia", ".aw": "Aruba",
            ".ax": "�& land Islands", ".az": "Azerbaijan", ".ba": "Bosnia and Herzegovina",
            ".bb": "Barbados", ".bd": "Bangladesh", ".be": "Belgium", ".bf": "Burkina Faso",
            ".bg": "Bulgaria", ".bh": "Bahrain", ".bi": "Burundi", ".bj": "Benin",
            ".bm": "Bermuda", ".bn": "Brunei Darussalam", ".bo": "Bolivia", ".br": "Brazil",
            ".bs": "Bahamas", ".bt": "Bhutan", ".bv": "Bouvet Island", ".bw": "Botswana",
            ".by": "Belarus", ".bz": "Belize", ".ca": "Canada", ".cc": "Cocos Islands",
            ".cd": "Democratic Republic of the Congo", ".cf": "Central African Republic",
            ".cg": "Republic of the Congo", ".ch": "Switzerland", ".ci": "Côte d'Ivoire",
            ".ck": "Cook Islands", ".cl": "Chile", ".cm": "Cameroon", ".cn": "China",
            ".co": "Colombia", ".cr": "Costa Rica", ".cu": "Cuba", ".cv": "Cape Verde",
            ".cw": "Curaçao", ".cx": "Christmas Island", ".cy": "Cyprus", ".cz": "Czech Republic",
            ".de": "Germany", ".dj": "Djibouti", ".dk": "Denmark", ".dm": "Dominica",
            ".do": "Dominican Republic", ".dz": "Algeria", ".ec": "Ecuador", ".ee": "Estonia",
            ".eg": "Egypt", ".er": "Eritrea", ".es": "Spain", ".et": "Ethiopia",
            ".eu": "European Union", ".fi": "Finland", ".fj": "Fiji", ".fk": "Falkland Islands",
            ".fm": "Federated States of Micronesia", ".fo": "Faroe Islands", ".fr": "France",
            ".ga": "Gabon", ".gb": "United Kingdom", ".gd": "Grenada", ".ge": "Georgia",
            ".gf": "French Guiana", ".gg": "Guernsey", ".gh": "Ghana", ".gi": "Gibraltar",
            ".gl": "Greenland", ".gm": "Gambia", ".gn": "Guinea", ".gp": "Guadeloupe",
            ".gq": "Equatorial Guinea", ".gr": "Greece", ".gs": "South Georgia and the South Sandwich Islands",
            ".gt": "Guatemala", ".gu": "Guam", ".gw": "Guinea-Bissau", ".gy": "Guyana",
            ".hk": "Hong Kong", ".hm": "Heard Island and McDonald Islands", ".hn": "Honduras",
            ".hr": "Croatia", ".ht": "Haiti", ".hu": "Hungary", ".id": "Indonesia",
            ".ie": "Ireland", ".il": "Israel", ".im": "Isle of Man", ".in": "India",
            ".io": "British Indian Ocean Territory", ".iq": "Iraq", ".ir": "Iran",
            ".is": "Iceland", ".it": "Italy", ".je": "Jersey", ".jm": "Jamaica",
            ".jo": "Jordan", ".jp": "Japan", ".ke": "Kenya", ".kg": "Kyrgyzstan",
            ".kh": "Cambodia", ".ki": "Kiribati", ".km": "Comoros", ".kn": "Saint Kitts and Nevis",
            ".kp": "North Korea", ".kr": "South Korea", ".kw": "Kuwait", ".ky": "Cayman Islands",
            ".kz": "Kazakhstan", ".la": "Laos", ".lb": "Lebanon", ".lc": "Saint Lucia",
            ".li": "Liechtenstein", ".lk": "Sri Lanka", ".lr": "Liberia", ".ls": "Lesotho",
            ".lt": "Lithuania", ".lu": "Luxembourg", ".lv": "Latvia", ".ly": "Libya",
            ".ma": "Morocco", ".mc": "Monaco", ".md": "Moldova", ".me": "Montenegro",
            ".mf": "Saint Martin", ".mg": "Madagascar", ".mh": "Marshall Islands",
            ".mk": "North Macedonia", ".ml": "Mali", ".mm": "Myanmar", ".mn": "Mongolia",
            ".mo": "Macao", ".mp": "Northern Mariana Islands", ".mq": "Martinique",
            ".mr": "Mauritania", ".ms": "Montserrat", ".mt": "Malta", ".mu": "Mauritius",
            ".mv": "Maldives", ".mw": "Malawi", ".mx": "Mexico", ".my": "Malaysia",
            ".mz": "Mozambique", ".na": "Namibia", ".nc": "New Caledonia", ".ne": "Niger",
            ".nf": "Norfolk Island", ".ng": "Nigeria", ".ni": "Nicaragua", ".nl": "Netherlands",
            ".no": "Norway", ".np": "Nepal", ".nr": "Nauru", ".nu": "Niue",
            ".nz": "New Zealand", ".om": "Oman", ".pa": "Panama", ".pe": "Peru",
            ".pf": "French Polynesia", ".pg": "Papua New Guinea", ".ph": "Philippines",
            ".pk": "Pakistan", ".pl": "Poland", ".pm": "Saint Pierre and Miquelon",
            ".pn": "Pitcairn", ".pr": "Puerto Rico", ".ps": "Palestine", ".pt": "Portugal",
            ".pw": "Palau", ".py": "Paraguay", ".qa": "Qatar", ".re": "Réunion",
            ".ro": "Romania", ".rs": "Serbia", ".ru": "Russia", ".rw": "Rwanda",
            ".sa": "Saudi Arabia", ".sb": "Solomon Islands", ".sc": "Seychelles",
            ".sd": "Sudan", ".se": "Sweden", ".sg": "Singapore", ".sh": "Saint Helena",
            ".si": "Slovenia", ".sj": "Svalbard and Jan Mayen", ".sk": "Slovakia",
            ".sl": "Sierra Leone", ".sm": "San Marino", ".sn": "Senegal", ".so": "Somalia",
            ".sr": "Suriname", ".ss": "South Sudan", ".st": "São Tomé and Príncipe",
            ".sv": "El Salvador", ".sx": "Sint Maarten", ".sy": "Syria", ".sz": "Eswatini",
            ".tc": "Turks and Caicos Islands", ".td": "Chad", ".tf": "French Southern Territories",
            ".tg": "Togo", ".th": "Thailand", ".tj": "Tajikistan", ".tk": "Tokelau",
            ".tl": "Timor-Leste", ".tm": "Turkmenistan", ".tn": "Tunisia", ".to": "Tonga",
            ".tp": "East Timor", ".tr": "Turkey", ".tt": "Trinidad and Tobago", ".tv": "Tuvalu",
            ".tw": "Taiwan", ".tz": "Tanzania", ".ua": "Ukraine", ".ug": "Uganda",
            ".uk": "United Kingdom", ".um": "United States Minor Outlying Islands", ".us": "United States",
            ".uy": "Uruguay", ".uz": "Uzbekistan", ".va": "Vatican City", ".vc": "Saint Vincent and the Grenadines",
            ".ve": "Venezuela", ".vg": "British Virgin Islands", ".vi": "U.S. Virgin Islands",
            ".vn": "Vietnam", ".vu": "Vanuatu", ".wf": "Wallis and Futuna", ".ws": "Samoa",
            ".ye": "Yemen", ".yt": "Réunion", ".yu": "Yugoslavia", ".za": "South Africa",
            ".zm": "Zambia", ".zw": "Zimbabwe"
        }

        for ccTLD in ccTLD_to_region:
            if primary_domain.endswith(ccTLD):
                return ccTLD_to_region[ccTLD]
        return "Global"

def train_model():
    global pipeline, model_trained
    if not ML_AVAILABLE:
        print("ML not available - skipping model training")
        return False

    if pipeline is not None and model_trained:
        return True  # Already trained

    try:
        # Load and preprocess data
        urls_data = pd.read_csv(r'static/dataset/Phishing.csv')
        urls_data["url_type"] = urls_data["type"].replace({
            'benign': 0,
            'defacement': 1,
            'phishing': 2,
            'malware': 3
        })

        # Apply feature extraction
        urls_data['url_len'] = urls_data['url'].apply(lambda x: get_url_length(str(x)))
        urls_data['letters_count'] = urls_data['url'].apply(lambda x: count_letters(x))
        urls_data['digits_count'] = urls_data['url'].apply(lambda x: count_digits(x))
        urls_data['special_chars_count'] = urls_data['url'].apply(lambda x: count_special_chars(x))
        urls_data['shortened'] = urls_data['url'].apply(lambda x: has_shortening_service(x))
        urls_data['abnormal_url'] = urls_data['url'].apply(lambda x: abnormal_url(x))
        urls_data['secure_http'] = urls_data['url'].apply(lambda x: secure_http(x))
        urls_data['have_ip'] = urls_data['url'].apply(lambda x: have_ip_address(x))
        urls_data['pri_domain'] = urls_data['url'].apply(lambda x: extract_root_domain(x))
        urls_data['url_region'] = urls_data['pri_domain'].apply(lambda x: hash_encode(get_url_region(str(x))))
        urls_data['root_domain'] = urls_data['pri_domain'].apply(lambda x: hash_encode(str(x)))
        urls_data.fillna(0, inplace=True)

        # Prepare training data
        x = urls_data.drop(columns=['url_type', 'url', 'pri_domain', 'type'])
        y = pd.to_numeric(urls_data['url_type'], errors='coerce')
        valid_mask = y.notna()
        x = x.loc[valid_mask]
        y = y.loc[valid_mask].astype(int)

        # Additional data cleaning
        x = x.fillna(0)
        x = x.replace([np.inf, -np.inf], 0)

        # Memory optimization: limit training data size
        max_samples = min(10000, len(x))  # Cap at 10k samples for memory efficiency
        if len(x) > max_samples:
            print(f"Limiting training data to {max_samples} samples for memory efficiency")
            indices = np.random.choice(len(x), max_samples, replace=False)
            x = x.iloc[indices]
            y = y.iloc[indices]

        print(f"Training data shape: {x.shape}")
        print(f"Target distribution: {y.value_counts()}")

        x_train, x_test, y_train, y_test = train_test_split(x, y, test_size=0.3, random_state=42)

        # Train the model with memory-efficient settings
        pipeline = Pipeline([
            ('classifier', RandomForestClassifier(
                n_estimators=50,  # Reduced from default 100
                max_depth=15,     # Limit tree depth
                min_samples_split=10,
                min_samples_leaf=5,
                n_jobs=1,  # Use single thread to avoid memory issues
                random_state=42
            ))
        ])

        try:
            pipeline.fit(x_train, y_train)
            model_trained = True
            print("Model trained successfully")
            return True
        except Exception as e:
            print(f"RandomForest training failed: {e}")
            # Fallback to LogisticRegression (more memory efficient)
            try:
                pipeline = Pipeline([
                    ('classifier', LogisticRegression(
                        random_state=42,
                        max_iter=1000,
                        solver='lbfgs',
                        n_jobs=1
                    ))
                ])
                pipeline.fit(x_train, y_train)
                model_trained = True
                print("Fallback model (LogisticRegression) trained successfully")
                return True
            except Exception as e2:
                print(f"Fallback model training also failed: {e2}")
                return False

    except Exception as e:
        print(f"Model training failed: {e}")
        return False

# Train the model when module loads (only in production/on Render)
import os
if os.environ.get('RENDER') or os.environ.get('PRODUCTION') or not os.path.exists('.git'):  # Detect production environment
    # Disable automatic training on module import to avoid memory issues on Render
    # Model will be trained lazily on first prediction request
    print("Running in production mode - model training will happen on first prediction request")

def index(request):
    return render(request,'index.html')

def register(request):
    if request.method == 'POST':
        username = request.POST['username']
        email = request.POST['email']
        password = request.POST['password']
        password2 = request.POST['password2']

        if password == password2:
            if User.objects.filter(email=email).exists():
                messages.info(request,'Email already exists')
                return render(request,'register.html')
            elif User.objects.filter(username=username).exists():
                messages.info(request,'Username already exists')
                return render(request,'register.html')
            else:
                user = User.objects.create_user(username=username,email=email,password=password)
                user.save()
                return HttpResponseRedirect('/login')
        else:
            messages.info(request,'Password not matching')
            return render(request,'register.html')
    else:
        return render(request,'register.html')

def login(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']

        user = auth.authenticate(username=username,password=password)

        if user is not None:
            auth.login(request,user)
            return HttpResponseRedirect('/predict')
        else:
            messages.info(request,'Invalid credentials')
            return render(request,'login.html')
    else:
        return render(request,'login.html')

def adminlogin(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']

        user = auth.authenticate(username=username,password=password)

        if user is not None and user.is_superuser:
            auth.login(request,user)
            return HttpResponseRedirect('/adminhome')
        else:
            messages.info(request,'Invalid credentials or not an admin')
            return render(request,'adminlogin.html')
    else:
        return render(request,'adminlogin.html')

def adminhome(request):
    if request.user.is_superuser:
        data = MaliciousBot.objects.all()
        return render(request,'adminhome.html',{'data':data})
    else:
        return HttpResponseRedirect('/adminlogin')

def predict(request):
    if request.method == 'POST':
        url = request.POST['url']
        user = request.user

        if not ML_AVAILABLE:
            # Mock response for local development
            prediction_result = "Mock prediction: URL appears safe (ML not available)"
            prediction_type = "Safe"
            confidence = "N/A"
        else:
            try:
                # Lazy train model on first prediction if not already trained
                if not model_trained:
                    print("Training model on first prediction request...")
                    train_model()

                # Extract features from the URL
                url_len = get_url_length(str(url))
                letters_count = count_letters(url)
                digits_count = count_digits(url)
                special_chars_count = count_special_chars(url)
                shortened = has_shortening_service(url)
                abnormal = abnormal_url(url)
                secure = secure_http(url)
                have_ip = have_ip_address(url)
                pri_domain = extract_root_domain(url)
                url_region = hash_encode(get_url_region(str(pri_domain)))
                root_domain = hash_encode(str(pri_domain))

                # Create feature array
                features = np.array([[url_len, letters_count, digits_count, special_chars_count,
                                    shortened, abnormal, secure, have_ip, url_region, root_domain]])

                # Make prediction
                if pipeline is not None and model_trained:
                    prediction = pipeline.predict(features)[0]
                    prediction_proba = pipeline.predict_proba(features)[0]

                    # Map prediction to type
                    type_mapping = {0: 'Benign', 1: 'Defacement', 2: 'Phishing', 3: 'Malware'}
                    prediction_type = type_mapping.get(prediction, 'Unknown')

                    # Calculate confidence
                    confidence = f"{max(prediction_proba) * 100:.2f}%"

                    prediction_result = f"URL classified as: {prediction_type} (Confidence: {confidence})"
                else:
                    prediction_result = "Model not trained yet. Please try again later."
                    prediction_type = "Unknown"
                    confidence = "N/A"

            except Exception as e:
                prediction_result = f"Error during prediction: {str(e)}"
                prediction_type = "Error"
                confidence = "N/A"

        # Save to database
        try:
            MaliciousBot.objects.create(
                user=user,
                url=url,
                prediction=prediction_result,
                prediction_type=prediction_type,
                confidence=confidence
            )
        except Exception as e:
            print(f"Database save error: {e}")

        return render(request, 'predict.html', {
            'prediction': prediction_result,
            'url': url
        })
    else:
        return render(request, 'predict.html')

def data(request):
    if not request.user.is_authenticated:
        return HttpResponseRedirect('/login')

    if not ML_AVAILABLE:
        # Mock data for local development
        mock_data = [
            {'url': 'https://example.com', 'prediction': 'Mock: Benign', 'prediction_type': 'Benign', 'confidence': 'N/A', 'timestamp': '2024-01-01'},
            {'url': 'http://suspicious-site.ru', 'prediction': 'Mock: Phishing', 'prediction_type': 'Phishing', 'confidence': 'N/A', 'timestamp': '2024-01-02'},
        ]
        return render(request, 'data.html', {'data': mock_data})

    try:
        user_data = MaliciousBot.objects.filter(user=request.user).order_by('-timestamp')
        data_list = []
        for item in user_data:
            data_list.append({
                'url': item.url,
                'prediction': item.prediction,
                'prediction_type': item.prediction_type,
                'confidence': item.confidence,
                'timestamp': item.timestamp.strftime('%Y-%m-%d %H:%M:%S') if item.timestamp else 'N/A'
            })
        return render(request, 'data.html', {'data': data_list})
    except Exception as e:
        print(f"Error retrieving data: {e}")
        return render(request, 'data.html', {'data': [], 'error': 'Unable to load data'})

def logout(request):
    auth.logout(request)
    return HttpResponseRedirect('/')