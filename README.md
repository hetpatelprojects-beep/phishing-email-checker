# Phishing Email Checker

An **educational prototype** that rates how much an email's text looks like the phishing and scam emails a machine-learning model was trained on, and shows extra warning signs found in the email's headers and links.

> **This is not a security product.** It will miss phishing emails and it will wrongly flag legitimate ones. Never rely on it alone, and never click links in emails you do not trust.

Built by Het Patel as a cyber security project.

## What it does

You upload an `.eml` file (or paste the text of an email) and the app shows:

- **A risk level** from the text of the email: *High risk*, *Suspicious*, or *No strong warning signs*.
- **Other warning signs**, shown as evidence only: replies going to a different domain than the sender, failed SPF/DKIM/DMARC sender checks, link text that does not match where the link goes, links that use a numeric address, link shorteners, the `name@` trick and lookalike characters.

The model works on **English emails only**.

## Run it yourself

```
pip install -r requirements.txt
streamlit run app.py
```

Running it locally is also the safest way to check a private email, because nothing leaves your computer.

## How it works

1. The subject and body are cleaned (HTML, links, email addresses and numbers removed, lowercase).
2. The text is turned into TF-IDF features (single words and two-word phrases) using a vocabulary of about 10,900 words.
3. A logistic regression model produces a score. Two cutoffs, chosen from cross-validation, turn the score into a risk level.
4. Header and link warning signs are computed separately and are **not** part of the score. In our tests, adding them to the model helped in one year and hurt badly in another, so they are shown as evidence for a person to judge.

## Training data

- The Kaggle *Phishing Email Dataset* (naserabdullahalam), which merges six public collections: CEAS 2008, Enron, Ling-Spam, Nazario, Nigerian Fraud and SpamAssassin.
- *Phishing Pot* (rf-peixoto), a collection of real phishing emails gathered with honeypots, licensed **CC BY-NC 4.0**.
- A private sample of modern legitimate emails from the author's own mailbox. **These emails are not published**, and the vocabulary was restricted to words that appear in at least three different sources, so names and other personal details cannot be recovered from the model.

At most 2,500 emails per source and class were used, English only.

## Results

The most realistic test uses modern email from **senders the model never saw during training** (4,290 emails: 1,790 legitimate and 2,500 phishing). The AUC was 0.923.

| Alarm level | Phishing caught | False alarms on legitimate email |
|---|---|---|
| Strictest cutoff | about 37% | about 1% |
| **High risk** (used by the app) | **about 51%** | **about 2%** |
| Moderate cutoff | about 69% | about 5% |
| **Suspicious** (used by the app) | **about 81%** | **about 10%** |

Because real email is mostly legitimate, many alerts will still be false alarms. If only 1 in 100 emails were phishing, then at the *High risk* level roughly four out of five alerts would be false.

## Limitations

- **English only.** About 60% of the phishing collection is not in English, so the model was deliberately built for English email.
- **Legitimate email comes from one person's mailbox**, so the model may flag legitimate email that looks different from it. In a test on older legitimate mail from other sources, an earlier version of the model flagged far more legitimate email than on the author's own mailbox.
- **Weak on credential phishing** (fake password-expiry and account-verification messages). An earlier version caught only about 57% of such emails at a 2% false-alarm setting.
- **Phishing changes quickly.** The model was trained on data up to October 2026 and needs regular retraining.
- **Near-duplicate phishing templates** appear in the data, so results on the phishing side are probably optimistic.
- **Text only.** Images, QR codes, attachments and live link-reputation checks are not used.

## Privacy

The app checks the email in memory and does not store it. If you use a **hosted copy**, an uploaded email is still sent to the hosting server, so please do not upload private or sensitive emails to the public demo.

## Credits and license

- Kaggle *Phishing Email Dataset*: https://www.kaggle.com/datasets/naserabdullahalam/phishing-email-dataset (see the dataset page for the licenses of its source collections).
- *Phishing Pot* by rf-peixoto: https://github.com/rf-peixoto/phishing_pot (CC BY-NC 4.0).
- Built with scikit-learn and Streamlit.

Because of the licenses of the training data, this project is for **non-commercial, educational use only**.

## Files

| File | Purpose |
|---|---|
| `app.py` | The Streamlit app |
| `model_v3.joblib` | The trained logistic regression model |
| `vectorizer_v3.joblib` | The TF-IDF vectorizer and its vocabulary |
| `cutoffs_v3.json` | The score cutoffs for the risk levels |
| `requirements.txt` | Package versions |
