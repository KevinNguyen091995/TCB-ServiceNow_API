import json
import pandas as pd

full_asset_dataframe = pd.DataFrame()

file_name = "2023-06-01_DataDog"

f = open(f"Datadog_Reports/{file_name}.json")

test = json.load(f)

for x in test['rows']:
    full_asset_dataframe = pd.concat([full_asset_dataframe, pd.DataFrame({x['display_name']})])

full_asset_dataframe.to_csv(f"Datadog_Reports/{file_name}.csv",index=False)