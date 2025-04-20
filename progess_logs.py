import pandas as pd
from loguru import logger
from datetime import datetime, timedelta
import argparse
import sys

# Konfiguracja loggera
logger.remove()
logger.add(sys.stdout, colorize=True, format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{message}</cyan>")

def load_logs(csv_path: str) -> pd.DataFrame:
    """Wczytuje logi z pliku CSV z użyciem kodowania latin1"""
    logger.info(f"Ładowanie logów z pliku: {csv_path}")
    try:
        # Wczytaj z wymuszonym kodowaniem latin1
        df = pd.read_csv(
            csv_path,
            parse_dates=['Time'],
            encoding='latin1',
            on_bad_lines='warn'
        )
        
        # Konwersja czasu z obsługą błędów
        df['Time'] = pd.to_datetime(
            df['Time'], 
            format='%a %b %d %H:%M:%S %Y', 
            errors='coerce'
        )
        
        # Usuń wiersze z nieprawidłowymi datami
        df = df.dropna(subset=['Time'])
        
        logger.success(f"Pomyślnie wczytano {len(df)} zdarzeń (kodowanie: latin1)")
        return df
        
    except Exception as e:
        logger.error(f"Błąd podczas wczytywania pliku: {e}")
        raise

def filter_logs(
    df: pd.DataFrame,
    log_types: list = None,
    sources: list = None,
    time_range: tuple = None,
    event_types: list = None,
    event_ids: list = None,
    message_contains: str = None
) -> pd.DataFrame:
    """Filtruje logi według podanych kryteriów"""
    original_count = len(df)
    
    if log_types:
        df = df[df['Event'].isin(log_types)]
    if sources:
        df = df[df['Source'].isin(sources)]
    if event_types:
        df = df[df['Event_Type'].isin(event_types)]
    if event_ids:
        df = df[df['Event_ID'].isin(event_ids)]
    if message_contains:
        df = df[df['Message'].str.contains(message_contains, case=False, na=False)]
    if time_range:
        start, end = time_range
        df = df[(df['Time'] >= start) & (df['Time'] <= end)]
    
    logger.info(f"Przefiltrowano: {len(df)}/{original_count} zdarzeń")
    return df

def show_stats(df: pd.DataFrame):
    """Wyświetla statystyki logów"""
    if df.empty:
        logger.warning("Brak danych do wyświetlenia statystyk")
        return
    
    logger.info("\n=== STATYSTYKI ===")
    logger.info(f"Łączna liczba: {len(df)} zdarzeń")
    logger.info(f"Zakres czasowy: {df['Time'].min()} - {df['Time'].max()}")
    
    logger.info("\nRozkład typów zdarzeń:")
    logger.info(df['Event_Type'].value_counts().to_string())
    
    logger.info("\nTop 5 źródeł:")
    logger.info(df['Source'].value_counts().head(5).to_string())

def save_results(df: pd.DataFrame, output_path: str):
    """Zapisuje wyniki w odpowiednim formacie"""
    if output_path.endswith('.csv'):
        df.to_csv(output_path, index=False, encoding='utf-8-sig')
    elif output_path.endswith('.xlsx'):
        df.to_excel(output_path, index=False)
    elif output_path.endswith('.json'):
        df.to_json(output_path, orient='records', force_ascii=False)
    logger.success(f"Zapisano wyniki do: {output_path}")

def main():
    parser = argparse.ArgumentParser(description='Filtr logów Windows')
    parser.add_argument('input', help='Plik wejściowy CSV')
    parser.add_argument('output', help='Plik wynikowy')
    parser.add_argument('--log-types', nargs='+', help='Filtruj po typie logu')
    parser.add_argument('--sources', nargs='+', help='Filtruj po źródle')
    parser.add_argument('--event-types', nargs='+', help='Filtruj po typie zdarzenia')
    parser.add_argument('--event-ids', nargs='+', type=int, help='Filtruj po ID zdarzenia')
    parser.add_argument('--message-contains', help='Filtruj po zawartości wiadomości')
    parser.add_argument('--start-time', help='Początek zakresu czasowego')
    parser.add_argument('--end-time', help='Koniec zakresu czasowego')
    
    args = parser.parse_args()
    
    try:
        # Wczytaj i przetwórz logi
        df = load_logs(args.input)
        
        # Parsuj zakres czasowy
        time_range = None
        if args.start_time or args.end_time:
            start = datetime.strptime(args.start_time, '%Y-%m-%d') if args.start_time else datetime.min
            end = datetime.strptime(args.end_time, '%Y-%m-%d') if args.end_time else datetime.max
            time_range = (start, end)
        
        # Filtruj logi
        filtered_df = filter_logs(
            df,
            log_types=args.log_types,
            sources=args.sources,
            event_types=args.event_types,
            event_ids=args.event_ids,
            message_contains=args.message_contains,
            time_range=time_range
        )
        
        # Wyświetl statystyki i zapisz wyniki
        show_stats(filtered_df)
        save_results(filtered_df, args.output)
        
    except Exception as e:
        logger.error(f"Błąd: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()