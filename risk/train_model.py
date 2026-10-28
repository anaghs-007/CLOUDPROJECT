#!/usr/bin/env python3
import json
import os
import pickle
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import precision_recall_fscore_support, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler


ROOT = os.path.dirname(os.path.dirname(__file__))


def train_models():
    user_rows = []
    workload_rows = []
    with open(os.path.join(ROOT, 'risk', 'training_data.json'), 'r', encoding='utf-8') as handle:
        payload = json.load(handle)
    for item in payload.get('users', []):
        user_rows.append((item['features'], item['label']))
    for item in payload.get('workloads', []):
        workload_rows.append((item['features'], item['label']))

    models = {}
    for name, rows in {'user': user_rows, 'workload': workload_rows}.items():
        X = [row[0] for row in rows]
        y = [row[1] for row in rows]
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
        model = Pipeline([
            ('scaler', StandardScaler()),
            ('clf', LogisticRegression(class_weight='balanced', max_iter=1000))
        ])
        model.fit(X_train, y_train)
        preds = model.predict(X_test)
        proba = model.predict_proba(X_test)[:, 1]
        precision, recall, _, _ = precision_recall_fscore_support(y_test, preds, average='binary', zero_division=0)
        roc = roc_auc_score(y_test, proba)
        print(f'{name}: precision={precision:.4f} recall={recall:.4f} ROC-AUC={roc:.4f}')
        with open(os.path.join(ROOT, f'{name}_model.pkl'), 'wb') as handle:
            pickle.dump(model, handle)
        with open(os.path.join(ROOT, f'{name}_weights.json'), 'w', encoding='utf-8') as handle:
            json.dump({'model': name, 'coef': model.named_steps['clf'].coef_.tolist(), 'intercept': model.named_steps['clf'].intercept_.tolist()}, handle)
        models[name] = model
    return models


if __name__ == '__main__':
    train_models()
