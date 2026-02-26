#!/bin/bash
# ------------------------------------------------------------------
# Cost Guardrail: Zero-Spend Budget
# Prerequisite: AWS CLI configured with Billing permissions
# ------------------------------------------------------------------

set -e

ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
EMAIL_ADDRESS="INSERT_YOUR_EMAIL@HERE.COM"

echo "Creating Zero-Spend Budget for Account: $ACCOUNT_ID"

aws budgets create-budget \
    --account-id $ACCOUNT_ID \
    --budget '{
        "BudgetName": "Zero-Spend-Guardrail",
        "BudgetLimit": {
            "Amount": "1.00",
            "Unit": "USD"
        },
        "CostFilters": {},
        "CostTypes": {
            "IncludeTax": true,
            "IncludeSubscription": true,
            "UseBlended": false,
            "IncludeRefund": false,
            "IncludeCredit": false,
            "IncludeUpfront": true,
            "IncludeRecurring": true,
            "IncludeOtherSubscription": true,
            "IncludeSupport": true,
            "IncludeDiscount": true,
            "UseAmortized": false
        },
        "TimeUnit": "MONTHLY",
        "BudgetType": "COST"
    }' \
    --notifications-with-subscribers '[
        {
            "Notification": {
                "NotificationType": "ACTUAL",
                "ComparisonOperator": "GREATER_THAN",
                "Threshold": 100,
                "ThresholdType": "PERCENTAGE"
            },
            "Subscribers": [
                {
                    "SubscriptionType": "EMAIL",
                    "Address": "'$EMAIL_ADDRESS'"
                }
            ]
        }
    ]'

echo "Budget created. You will be emailed if spend > $0.01."
