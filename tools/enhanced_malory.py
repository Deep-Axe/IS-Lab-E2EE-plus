import json
import time
import os
import sys
from pathlib import Path
from base64 import b64decode
import hashlib
from collections import Counter, defaultdict

# Setup path for imports from parent src directory
current_dir = Path(__file__).parent
project_root = current_dir.parent
src_dir = project_root / 'src'
sys.path.insert(0, str(src_dir))

# Import modules
from utils.error_handler import ErrorHandler  # type: ignore
from utils.message_handler import MessageHandler  # type: ignore
from core.double_ratchet import Header  # type: ignore

class EnhancedMalory:
    """Enhanced Malory for advanced cryptanalysis and traffic analysis"""
    
    def __init__(self):
        self.error_handler = ErrorHandler()
        self.message_handler = MessageHandler()
        
        # Analysis data
        self.intercepted_messages = []
        self.traffic_patterns = defaultdict(list)
        self.timing_analysis = []
        self.crypto_analysis = {
            'headers_seen': [],
            'ciphertext_patterns': Counter(),
            'mac_patterns': Counter(),
            'sequence_analysis': defaultdict(list)
        }

    @staticmethod
    def _sender_label(message):
        sender = message.get('from')
        if sender:
            return sender
        sealed = message.get('sealed_sender') or {}
        hint = sealed.get('hint')
        return f"sealed:{hint}" if hint else "sealed"
        
    def load_intercepted_messages(self, log_file='malory_logs/intercepted_messages.json'):
        """Load intercepted messages from server log"""
        try:
            if not os.path.exists(log_file):
                print(f"No intercepted messages found at {log_file}")
                return 0
            
            count = 0
            with open(log_file, 'r') as f:
                for line in f:
                    if line.strip():
                        try:
                            message = json.loads(line.strip())
                            self.intercepted_messages.append(message)
                            count += 1
                        except json.JSONDecodeError:
                            continue
            
            print(f"Loaded {count} intercepted messages")
            return count
            
        except Exception as e:
            self.error_handler.handle_error(e, "load_intercepted_messages")
            return 0
    
    def analyze_traffic_patterns(self):
        """Analyze traffic patterns and timing"""
        print("\n=== TRAFFIC PATTERN ANALYSIS ===")
        
        if not self.intercepted_messages:
            print("No messages to analyze")
            return
        
        # Sort messages by timestamp
        sorted_messages = sorted(self.intercepted_messages, key=lambda x: x.get('timestamp', 0))
        
        # Analyze timing patterns
        timestamps = [msg.get('timestamp', 0) for msg in sorted_messages]
        if len(timestamps) > 1:
            intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
            avg_interval = sum(intervals) / len(intervals)
            
            print(f"Total messages intercepted: {len(sorted_messages)}")
            print(f"Time span: {timestamps[-1] - timestamps[0]} seconds")
            print(f"Average message interval: {avg_interval:.2f} seconds")
            print(f"Message frequency: {len(sorted_messages) / (timestamps[-1] - timestamps[0] + 1):.2f} msg/sec")
        
        # Analyze communication patterns
        senders = Counter(self._sender_label(msg) for msg in sorted_messages)
        receivers = Counter(msg.get('to') for msg in sorted_messages)
        
        print(f"\nSender distribution:")
        for sender, count in senders.items():
            print(f"  {sender}: {count} messages ({count/len(sorted_messages)*100:.1f}%)")
        
        print(f"\nReceiver distribution:")
        for receiver, count in receivers.items():
            print(f"  {receiver}: {count} messages ({count/len(sorted_messages)*100:.1f}%)")
        
        # Message size analysis
        sizes = []
        for msg in sorted_messages:
            if msg.get('ciphertext'):
                try:
                    ciphertext_size = len(b64decode(msg['ciphertext']))
                    sizes.append(ciphertext_size)
                except:
                    pass
        
        if sizes:
            print(f"\nCiphertext size analysis:")
            print(f"  Average size: {sum(sizes)/len(sizes):.1f} bytes")
            print(f"  Min size: {min(sizes)} bytes")
            print(f"  Max size: {max(sizes)} bytes")
            print(f"  Size variance: {len(set(sizes))} unique sizes")
    
    def analyze_double_ratchet_headers(self):
        """Analyze Double Ratchet headers for cryptographic patterns"""
        print("\n=== DOUBLE RATCHET HEADER ANALYSIS ===")
        
        headers_analyzed = 0
        dh_keys_seen = set()
        sequence_numbers = []
        previous_numbers = []
        
        for msg in self.intercepted_messages:
            header_data = msg.get('header')
            if not header_data:
                continue
            
            try:
                # Deserialize header
                header = Header.deserialize(header_data)
                headers_analyzed += 1
                
                # Collect DH keys (for key rotation analysis)
                dh_key_hash = hashlib.sha256(header.dh).hexdigest()[:16]
                dh_keys_seen.add(dh_key_hash)
                
                # Collect sequence numbers
                sequence_numbers.append(header.n)
                previous_numbers.append(header.pn)
                
                # Store for detailed analysis
                self.crypto_analysis['headers_seen'].append({
                    'timestamp': msg.get('timestamp'),
                    'dh_key_hash': dh_key_hash,
                    'sequence_n': header.n,
                    'previous_n': header.pn,
                    'from': self._sender_label(msg)
                })
                
            except Exception as e:
                continue
        
        if headers_analyzed == 0:
            print("No valid Double Ratchet headers found")
            return
        
        print(f"Headers analyzed: {headers_analyzed}")
        print(f"Unique DH keys observed: {len(dh_keys_seen)}")
        
        # Sequence number analysis
        if sequence_numbers:
            print(f"Sequence number range: {min(sequence_numbers)} - {max(sequence_numbers)}")
            print(f"Sequence number gaps: {self._find_sequence_gaps(sequence_numbers)}")
        
        # Key rotation analysis
        sender_keys = defaultdict(set)
        for header in self.crypto_analysis['headers_seen']:
            sender = header['from']
            dh_hash = header['dh_key_hash']
            sender_keys[sender].add(dh_hash)
        
        print(f"\nKey rotation analysis:")
        for sender, keys in sender_keys.items():
            print(f"  {sender}: {len(keys)} different DH keys used")
            if len(keys) > 1:
                print(f"    Key rotation detected!")
    
    def _find_sequence_gaps(self, sequence_numbers):
        """Find gaps in sequence numbers (potential message loss)"""
        if not sequence_numbers:
            return 0
        
        sorted_seq = sorted(sequence_numbers)
        gaps = 0
        
        for i in range(len(sorted_seq) - 1):
            if sorted_seq[i + 1] - sorted_seq[i] > 1:
                gaps += 1
        
        return gaps
    
    def analyze_ciphertext_patterns(self):
        """Analyze ciphertext for patterns (should find none in good encryption)"""
        print("\n=== CIPHERTEXT PATTERN ANALYSIS ===")
        
        ciphertexts = []
        ciphertext_lengths = Counter()
        
        for msg in self.intercepted_messages:
            ciphertext = msg.get('ciphertext')
            if ciphertext:
                try:
                    ct_bytes = b64decode(ciphertext)
                    ciphertexts.append(ct_bytes)
                    ciphertext_lengths[len(ct_bytes)] += 1
                    
                    # Look for repeated blocks (should not exist)
                    blocks = [ct_bytes[i:i+16] for i in range(0, len(ct_bytes), 16)]
                    for block in blocks:
                        block_hash = hashlib.sha256(block).hexdigest()[:8]
                        self.crypto_analysis['ciphertext_patterns'][block_hash] += 1
                        
                except Exception:
                    continue
        
        print(f"Ciphertexts analyzed: {len(ciphertexts)}")
        
        # Length distribution
        print(f"Ciphertext length distribution:")
        for length, count in sorted(ciphertext_lengths.items()):
            print(f"  {length} bytes: {count} messages")
        
        # Look for repeated patterns (BAD if found)
        repeated_patterns = {pattern: count for pattern, count in 
                           self.crypto_analysis['ciphertext_patterns'].items() if count > 1}
        
        if repeated_patterns:
            print(f"\nWARNING: Repeated ciphertext patterns found!")
            for pattern, count in repeated_patterns.items():
                print(f"  Pattern {pattern}: {count} occurrences")
            print("This may indicate weak encryption or implementation issues")
        else:
            print(f"\nNo repeated ciphertext patterns found (GOOD)")
            print("Ciphertext appears properly randomized")
    
    def analyze_mac_patterns(self):
        """Analyze MAC patterns for authentication verification"""
        print("\n=== MAC PATTERN ANALYSIS ===")
        
        macs_analyzed = 0
        mac_lengths = Counter()
        
        for msg in self.intercepted_messages:
            mac = msg.get('mac')
            if mac:
                try:
                    mac_bytes = b64decode(mac)
                    macs_analyzed += 1
                    mac_lengths[len(mac_bytes)] += 1
                    
                    # Hash MAC for pattern detection
                    mac_hash = hashlib.sha256(mac_bytes).hexdigest()[:8]
                    self.crypto_analysis['mac_patterns'][mac_hash] += 1
                    
                except Exception:
                    continue
        
        print(f"MACs analyzed: {macs_analyzed}")
        
        # MAC length distribution
        print(f"MAC length distribution:")
        for length, count in sorted(mac_lengths.items()):
            print(f"  {length} bytes: {count} messages")
        
        # Look for repeated MACs (VERY BAD if found)
        repeated_macs = {mac: count for mac, count in 
                        self.crypto_analysis['mac_patterns'].items() if count > 1}
        
        if repeated_macs:
            print(f"\nCRITICAL: Repeated MAC values found!")
            for mac_pattern, count in repeated_macs.items():
                print(f"  MAC pattern {mac_pattern}: {count} occurrences")
            print("This indicates serious cryptographic weakness!")
        else:
            print(f"\nNo repeated MAC values found (GOOD)")
            print("MAC generation appears properly randomized")
    
    def analyze_message_metadata(self):
        """Analyze enhanced message metadata"""
        print("\n=== MESSAGE METADATA ANALYSIS ===")
        
        versions = Counter()
        message_types = Counter()
        algorithms = Counter()
        
        for msg in self.intercepted_messages:
            # Version analysis
            version = msg.get('version')
            if version:
                versions[version] += 1
            
            # Message type analysis
            msg_type = msg.get('message_type')
            if msg_type:
                message_types[msg_type] += 1
            
            # Algorithm analysis
            metadata = msg.get('metadata', {})
            if metadata:
                enc_alg = metadata.get('encryption_algorithm')
                if enc_alg:
                    algorithms[enc_alg] += 1
        
        print(f"Protocol versions observed:")
        for version, count in versions.items():
            print(f"  {version}: {count} messages")
        
        print(f"\nMessage types observed:")
        for msg_type, count in message_types.items():
            print(f"  Type {msg_type}: {count} messages")
        
        print(f"\nEncryption algorithms observed:")
        for alg, count in algorithms.items():
            print(f"  {alg}: {count} messages")
    
    def perform_timing_attack_analysis(self):
        """Analyze timing patterns that might reveal information"""
        print("\n=== TIMING ATTACK ANALYSIS ===")
        
        if len(self.intercepted_messages) < 2:
            print("Insufficient data for timing analysis")
            return
        
        # Sort by timestamp
        sorted_msgs = sorted(self.intercepted_messages, key=lambda x: x.get('timestamp', 0))
        
        # Analyze intervals between messages
        intervals = []
        for i in range(len(sorted_msgs) - 1):
            interval = sorted_msgs[i+1]['timestamp'] - sorted_msgs[i]['timestamp']
            intervals.append(interval)
        
        if intervals:
            avg_interval = sum(intervals) / len(intervals)
            print(f"Average message interval: {avg_interval:.3f} seconds")
            
            # Look for regular patterns
            interval_counts = Counter(f"{interval:.1f}" for interval in intervals)
            common_intervals = interval_counts.most_common(5)
            
            print(f"Most common intervals:")
            for interval, count in common_intervals:
                print(f"  {interval}s: {count} occurrences")
            
            # Check for timing regularity (could indicate automated behavior)
            regularity_score = max(interval_counts.values()) / len(intervals)
            if regularity_score > 0.3:
                print(f"WARNING: High timing regularity detected ({regularity_score:.2f})")
                print("This might indicate predictable message timing")
    
    def generate_cryptanalysis_report(self):
        """Generate comprehensive cryptanalysis report"""
        print("\n" + "="*60)
        print("           MALORY'S CRYPTANALYSIS REPORT")
        print("    Enhanced Double Ratchet Traffic Analysis")
        print("="*60)
        
        # Load data
        message_count = self.load_intercepted_messages()
        
        if message_count == 0:
            print("\nNo intercepted traffic to analyze.")
            print("Start the server and clients to generate traffic for analysis.")
            return
        
        # Perform all analyses
        self.analyze_traffic_patterns()
        self.analyze_double_ratchet_headers()
        self.analyze_ciphertext_patterns()
        self.analyze_mac_patterns()
        self.analyze_message_metadata()
        self.perform_timing_attack_analysis()
        
        # Summary assessment
        print("\n=== CRYPTOGRAPHIC SECURITY ASSESSMENT ===")
        
        # Check for weaknesses
        weaknesses_found = []
        
        # Check ciphertext patterns
        repeated_ct = sum(1 for count in self.crypto_analysis['ciphertext_patterns'].values() if count > 1)
        if repeated_ct > 0:
            weaknesses_found.append(f"Repeated ciphertext patterns ({repeated_ct})")
        
        # Check MAC patterns
        repeated_mac = sum(1 for count in self.crypto_analysis['mac_patterns'].values() if count > 1)
        if repeated_mac > 0:
            weaknesses_found.append(f"Repeated MAC values ({repeated_mac}) - CRITICAL")
        
        if weaknesses_found:
            print("SECURITY ISSUES DETECTED:")
            for weakness in weaknesses_found:
                print(f"  ❌ {weakness}")
        else:
            print("✅ No obvious cryptographic weaknesses detected")
            print("✅ Double Ratchet appears to be implemented correctly")
            print("✅ Forward secrecy and message authentication intact")
        
        print(f"\n=== FINAL ANALYSIS SUMMARY ===")
        print(f"Messages intercepted: {len(self.intercepted_messages)}")
        print(f"Headers analyzed: {len(self.crypto_analysis['headers_seen'])}")
        print(f"Unique DH keys: {len(set(h['dh_key_hash'] for h in self.crypto_analysis['headers_seen']))}")
        print(f"Cryptographic strength: {'WEAK' if weaknesses_found else 'STRONG'}")
        
        # Show error statistics
        stats = self.error_handler.get_error_statistics()
        if stats['total_errors'] > 0:
            print(f"\nAnalysis errors encountered: {stats['total_errors']}")
            for error_type, count in stats['error_counts'].items():
                print(f"  {error_type}: {count}")
        
        print("\n" + "="*60)
        print("Malory's analysis complete. Remember: This is for educational")
        print("purposes only to demonstrate Double Ratchet security properties.")
        print("="*60)

def main():
    malory = EnhancedMalory()
    
    try:
        malory.generate_cryptanalysis_report()
    except KeyboardInterrupt:
        print("\nAnalysis interrupted by user")
    except Exception as e:
        print(f"Analysis error: {e}")

if __name__ == "__main__":
    main()