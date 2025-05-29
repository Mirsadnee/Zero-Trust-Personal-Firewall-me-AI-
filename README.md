# Firewall Zero Trust me AI

Ky projekt është një zgjidhje e avancuar për sigurinë e rrjetit që përdor parimet e Zero Trust dhe inteligjencën artificiale për të mbrojtur sistemin tuaj nga kërcënimet e rrjetit.

## Veçoritë

- **Zero Trust Architecture**: Çdo lidhje dhe aplikacion trajtohet si i dyshimtë derisa të verifikohet
- **Analizë e Sjelljes me AI**: Përdor mësimin e makinerisë për të zbuluar modele të dyshimta në trafikun e rrjetit
- **Ndërfaqe Grafike**: GUI moderne dhe e lehtë për t'u përdorur në gjuhën shqipe
- **Monitorim në Kohë Reale**: Analizon trafikun e rrjetit në kohë reale
- **Mësim Automatik**: Përmirëson vazhdimisht modelin e tij bazuar në sjelljen e re të zbuluar

## Kërkesat e Sistemit

- Python 3.8 ose më i ri
- Windows 10/11
- Të drejta administratori për monitorimin e rrjetit
- 4GB RAM (minimum)
- 2GB hapësirë në disk

## Instalimi

1. Klono repozitorinë:
```bash
git clone https://github.com/username/zero-trust-firewall.git
cd zero-trust-firewall
```

2. Krijo një mjedis virtual Python:
```bash
python -m venv venv
```

3. Aktivizo mjedisin virtual:
```bash
# Në Windows
.\venv\Scripts\activate

# Në Linux/Mac
source venv/bin/activate
```

4. Instalo varësitë:
```bash
pip install -r requirements.txt
```

## Përdorimi

1. Hap PowerShell si administrator
2. Navigo te direktoria e projektit
3. Aktivizo mjedisin virtual
4. Ekzekuto skriptin:
```bash
python firewall_gui.py
```

5. Në ndërfaqen grafike:
   - Kliko "Nis Firewall-in" për të filluar monitorimin
   - Përdor "Ndalo Firewall-in" për të ndaluar monitorimin
   - Shiko logun e aktiviteteve për informacion në kohë reale
   - Monitoro statistikat e paketave të analizuara

## Varësitë

- scapy==2.5.0
- tensorflow==2.14.0
- numpy==1.24.3
- pandas==2.1.4
- scikit-learn==1.3.2
- psutil==5.9.6
- python-dotenv==1.0.0

## Kontributori

- Mrsad Neshati

## Licenca

Ky projekt është licencuar nën MIT License - shiko file-in [LICENSE](LICENSE) për detaje.

## Shënime të Rëndësishme

- Gjithmonë ekzekuto si administrator për akses të plotë në rrjet
- Sigurohu që antivirusi nuk bllokon funksionalitetin e firewall-it
- Bëj backup të rregullave dhe konfigurimeve të rëndësishme
- Kontrollo rregullisht logun për aktivitete të dyshimta # Zero-Trust-Personal-Firewall-me-AI-
