import os
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib 
import glob 



try:
    matplotlib.rcParams['font.family'] = 'DejaVu Sans'
    matplotlib.rcParams['font.sans-serif'] = ['DejaVu Sans']
    print("Matplotlib configured to use 'DejaVu Sans' font for Cyrillic support.")
except Exception as e:
    print(f"Warning: Failed to set 'DejaVu Sans' font. Cyrillic text might not display correctly. Error: {e}")
    print("Please ensure you have a Cyrillic-supporting font installed (e.g., 'DejaVu Sans').")





BASE_DIR = os.path.join(os.getcwd(), 'results')



TOOLS = ['gofilter', 'iptables', 'suricata', 'xdpfilter']
METRICS_FILES = {
    'bandwidth': 'bandwidth_vs_*',
    'cpu': 'system_cpu_vs_*',
    'memory': 'system_mem_vs_*'
}


METRIC_NAMES_RU = {
    'bandwidth': 'Пропускная способность (Мбит/с)',
    'cpu': 'Загрузка ЦП (%)',
    'memory': 'Использование памяти (%)'
}

X_AXIS_LABEL_RU = 'Количество правил / IP-адресов'

PLOTS_DIR = os.path.join(BASE_DIR, 'plots')


os.makedirs(PLOTS_DIR, exist_ok=True)
print(f"Plots will be saved in: {PLOTS_DIR}")


all_data = {metric: {} for metric in METRICS_FILES.keys()} 


print("\n--- Generating Individual Plots ---")
for tool in TOOLS:
    tool_path = os.path.join(BASE_DIR, tool)
    if not os.path.isdir(tool_path):
        print(f"Warning: Directory not found for tool '{tool}', skipping: {tool_path}")
        continue

    print(f"Processing tool: {tool}")
    for metric_key, file_pattern in METRICS_FILES.items():
        
        search_pattern = os.path.join(tool_path, f"{file_pattern}.csv")
        found_files = glob.glob(search_pattern)

        if not found_files:
            print(f"  Warning: Could not find {metric_key} CSV file for {tool} using pattern: {search_pattern}")
            continue

        
        csv_file = found_files[0]
        print(f"  Processing file: {os.path.basename(csv_file)}")

        try:
            df = pd.read_csv(csv_file)

            
            if df.empty or len(df.columns) < 2:
                print(f"  Warning: File '{os.path.basename(csv_file)}' is empty or has invalid format. Skipping.")
                continue

            
            all_data[metric_key][tool] = df

            
            x_col_name = df.columns[0] 
            y_col_name = df.columns[1] 

            plt.figure(figsize=(10, 6))
            
            plt.plot(df[x_col_name], df[y_col_name], marker='o', linestyle='-', markersize=4)

            
            plt.title(f'{METRIC_NAMES_RU[metric_key]} для {tool.capitalize()}') 
            plt.xlabel(X_AXIS_LABEL_RU) 
            plt.ylabel(METRIC_NAMES_RU[metric_key]) 
            plt.grid(True)
            plt.tight_layout() 

            
            plot_filename = f"{tool}_{metric_key}.png"
            plot_filepath = os.path.join(PLOTS_DIR, plot_filename)
            plt.savefig(plot_filepath)
            plt.close() 
            print(f"  Saved plot: {plot_filename}")

        except FileNotFoundError:
            print(f"  Error: File not found: {csv_file}")
        except pd.errors.EmptyDataError:
             print(f"  Error: File is empty: {csv_file}")
        except Exception as e:
            print(f"  Error processing file {csv_file}: {e}")



print("\n--- Generating Combined Plots ---")
for metric_key, metric_name_ru in METRIC_NAMES_RU.items():
    print(f"Generating combined plot for: {metric_key}") 

    plt.figure(figsize=(12, 7))

    data_for_metric = all_data[metric_key]

    if not data_for_metric:
        print(f"  No data found for metric '{metric_key}'. Skipping combined plot.")
        plt.close() 
        continue

    has_data = False
    for tool, df in data_for_metric.items():
        if df is not None and not df.empty and len(df.columns) >= 2:
            x_col_name = df.columns[0]
            y_col_name = df.columns[1]
            
            plt.plot(df[x_col_name], df[y_col_name], marker='o', linestyle='-', markersize=4, label=tool.capitalize())
            has_data = True
        else:
             print(f"  Skipping tool '{tool}' for combined {metric_key} plot (no valid data).")

    if not has_data:
        print(f"  No valid data series found for combined metric '{metric_key}'. Skipping plot.")
        plt.close()
        continue

    
    plt.title(f'Сравнение: {metric_name_ru}') 
    plt.xlabel(X_AXIS_LABEL_RU) 
    plt.ylabel(metric_name_ru) 
    plt.legend() 
    plt.grid(True)
    plt.tight_layout()

    
    plot_filename = f"combined_{metric_key}.png"
    plot_filepath = os.path.join(PLOTS_DIR, plot_filename)
    plt.savefig(plot_filepath)
    plt.close() 
    print(f"  Saved combined plot: {plot_filename}")

print("\n--- Script Finished ---")