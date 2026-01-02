#!/usr/bin/env python3
"""
NFA-Linux ML Sidecar Service

A gRPC-based machine learning inference service for network forensics.
Provides anomaly detection, traffic classification, and threat detection.
"""

import asyncio
import logging
import os
import signal
import sys
import time
from concurrent import futures
from typing import Dict, List, Optional, Tuple

import grpc
import numpy as np
from grpc_reflection.v1alpha import reflection

# ML Libraries
try:
    import onnxruntime as ort
    ONNX_AVAILABLE = True
except ImportError:
    ONNX_AVAILABLE = False
    logging.warning("ONNX Runtime not available")

try:
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    import joblib
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    logging.warning("scikit-learn not available")

# Import generated protobuf modules
# These would be generated from ml_inference.proto
# For now, we'll create a mock implementation

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class ModelManager:
    """Manages ML models for inference"""
    
    def __init__(self, model_dir: str = "./models"):
        self.model_dir = model_dir
        self.models: Dict[str, any] = {}
        self.scalers: Dict[str, StandardScaler] = {}
        self.metadata: Dict[str, dict] = {}
        self.inference_counts: Dict[str, int] = {}
        self.total_latency: Dict[str, float] = {}
        self.start_time = time.time()
        
    def load_onnx_model(self, name: str, path: str) -> bool:
        """Load an ONNX model"""
        if not ONNX_AVAILABLE:
            logger.error("ONNX Runtime not available")
            return False
            
        try:
            # Create session options
            sess_options = ort.SessionOptions()
            sess_options.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
            sess_options.intra_op_num_threads = 4
            
            # Try to use GPU if available
            providers = ['CUDAExecutionProvider', 'CPUExecutionProvider']
            
            session = ort.InferenceSession(path, sess_options, providers=providers)
            
            self.models[name] = {
                'type': 'onnx',
                'session': session,
                'input_names': [i.name for i in session.get_inputs()],
                'output_names': [o.name for o in session.get_outputs()],
                'input_shapes': [i.shape for i in session.get_inputs()],
            }
            
            self.metadata[name] = {
                'name': name,
                'version': '1.0',
                'framework': 'onnx',
                'loaded_at': time.time(),
            }
            
            self.inference_counts[name] = 0
            self.total_latency[name] = 0.0
            
            logger.info(f"Loaded ONNX model: {name}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to load ONNX model {name}: {e}")
            return False
    
    def load_sklearn_model(self, name: str, path: str) -> bool:
        """Load a scikit-learn model"""
        if not SKLEARN_AVAILABLE:
            logger.error("scikit-learn not available")
            return False
            
        try:
            model = joblib.load(path)
            
            self.models[name] = {
                'type': 'sklearn',
                'model': model,
            }
            
            # Try to load associated scaler
            scaler_path = path.replace('.joblib', '_scaler.joblib')
            if os.path.exists(scaler_path):
                self.scalers[name] = joblib.load(scaler_path)
            
            self.metadata[name] = {
                'name': name,
                'version': '1.0',
                'framework': 'sklearn',
                'loaded_at': time.time(),
            }
            
            self.inference_counts[name] = 0
            self.total_latency[name] = 0.0
            
            logger.info(f"Loaded sklearn model: {name}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to load sklearn model {name}: {e}")
            return False
    
    def predict(self, name: str, features: np.ndarray) -> Tuple[np.ndarray, float]:
        """Run inference on a model"""
        if name not in self.models:
            raise ValueError(f"Model {name} not found")
        
        start_time = time.time()
        model_info = self.models[name]
        
        # Apply scaler if available
        if name in self.scalers:
            features = self.scalers[name].transform(features)
        
        if model_info['type'] == 'onnx':
            session = model_info['session']
            input_name = model_info['input_names'][0]
            
            # Ensure correct dtype
            features = features.astype(np.float32)
            
            outputs = session.run(None, {input_name: features})
            result = outputs[0]
            
        elif model_info['type'] == 'sklearn':
            model = model_info['model']
            
            if hasattr(model, 'predict_proba'):
                result = model.predict_proba(features)
            else:
                result = model.predict(features)
                if result.ndim == 1:
                    result = result.reshape(-1, 1)
        else:
            raise ValueError(f"Unknown model type: {model_info['type']}")
        
        latency = (time.time() - start_time) * 1000  # ms
        
        # Update statistics
        self.inference_counts[name] += 1
        self.total_latency[name] += latency
        
        return result, latency
    
    def get_model_info(self, name: Optional[str] = None) -> List[dict]:
        """Get information about loaded models"""
        if name:
            if name not in self.metadata:
                return []
            info = self.metadata[name].copy()
            info['inference_count'] = self.inference_counts.get(name, 0)
            total_lat = self.total_latency.get(name, 0)
            count = self.inference_counts.get(name, 1)
            info['avg_latency_ms'] = total_lat / count if count > 0 else 0
            return [info]
        
        result = []
        for name, meta in self.metadata.items():
            info = meta.copy()
            info['inference_count'] = self.inference_counts.get(name, 0)
            total_lat = self.total_latency.get(name, 0)
            count = self.inference_counts.get(name, 1)
            info['avg_latency_ms'] = total_lat / count if count > 0 else 0
            result.append(info)
        return result
    
    def get_uptime(self) -> float:
        """Get service uptime in seconds"""
        return time.time() - self.start_time


class AnomalyDetector:
    """Anomaly detection using Isolation Forest"""
    
    def __init__(self, contamination: float = 0.1, n_estimators: int = 100):
        self.contamination = contamination
        self.n_estimators = n_estimators
        self.model: Optional[IsolationForest] = None
        self.scaler: Optional[StandardScaler] = None
        self.threshold: float = 0.0
        self.is_fitted = False
        
    def fit(self, X: np.ndarray):
        """Fit the anomaly detector"""
        if not SKLEARN_AVAILABLE:
            raise RuntimeError("scikit-learn not available")
        
        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X)
        
        self.model = IsolationForest(
            contamination=self.contamination,
            n_estimators=self.n_estimators,
            random_state=42,
            n_jobs=-1
        )
        self.model.fit(X_scaled)
        
        # Calculate threshold from training data
        scores = self.model.decision_function(X_scaled)
        self.threshold = np.percentile(scores, self.contamination * 100)
        
        self.is_fitted = True
        logger.info(f"Anomaly detector fitted with threshold: {self.threshold}")
    
    def predict(self, X: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """Predict anomalies"""
        if not self.is_fitted:
            raise RuntimeError("Model not fitted")
        
        X_scaled = self.scaler.transform(X)
        
        # Get anomaly scores (higher = more normal)
        scores = self.model.decision_function(X_scaled)
        
        # Convert to anomaly scores (higher = more anomalous)
        anomaly_scores = -scores
        
        # Predict labels (-1 = anomaly, 1 = normal)
        predictions = self.model.predict(X_scaled)
        is_anomaly = predictions == -1
        
        return is_anomaly, anomaly_scores
    
    def save(self, path: str):
        """Save the model"""
        if not self.is_fitted:
            raise RuntimeError("Model not fitted")
        
        joblib.dump({
            'model': self.model,
            'scaler': self.scaler,
            'threshold': self.threshold,
        }, path)
        logger.info(f"Anomaly detector saved to {path}")
    
    def load(self, path: str):
        """Load the model"""
        data = joblib.load(path)
        self.model = data['model']
        self.scaler = data['scaler']
        self.threshold = data['threshold']
        self.is_fitted = True
        logger.info(f"Anomaly detector loaded from {path}")


class DNSTunnelingDetector:
    """DNS tunneling detection using character analysis and ML"""
    
    def __init__(self):
        self.model: Optional[any] = None
        self.scaler: Optional[StandardScaler] = None
        self.is_fitted = False
        
        # Thresholds for rule-based detection
        self.entropy_threshold = 3.5
        self.length_threshold = 50
        self.subdomain_threshold = 4
        
    def extract_features(self, domain: str) -> np.ndarray:
        """Extract features from a domain name"""
        features = []
        
        # Length features
        features.append(len(domain))
        
        # Label analysis
        labels = domain.split('.')
        features.append(len(labels))
        features.append(max(len(l) for l in labels) if labels else 0)
        features.append(np.mean([len(l) for l in labels]) if labels else 0)
        
        # Character distribution
        domain_lower = domain.lower()
        alpha_count = sum(1 for c in domain_lower if c.isalpha())
        digit_count = sum(1 for c in domain_lower if c.isdigit())
        special_count = sum(1 for c in domain_lower if not c.isalnum() and c != '.')
        
        total = len(domain_lower.replace('.', ''))
        if total > 0:
            features.append(alpha_count / total)
            features.append(digit_count / total)
            features.append(special_count / total)
        else:
            features.extend([0, 0, 0])
        
        # Entropy
        features.append(self._calculate_entropy(domain_lower))
        
        # Vowel/consonant ratio
        vowels = set('aeiou')
        vowel_count = sum(1 for c in domain_lower if c in vowels)
        consonant_count = alpha_count - vowel_count
        features.append(vowel_count / (consonant_count + 1))
        
        # N-gram entropy
        features.append(self._calculate_ngram_entropy(domain_lower, 2))
        features.append(self._calculate_ngram_entropy(domain_lower, 3))
        
        return np.array(features, dtype=np.float32)
    
    def _calculate_entropy(self, s: str) -> float:
        """Calculate Shannon entropy"""
        if not s:
            return 0.0
        
        freq = {}
        for c in s:
            freq[c] = freq.get(c, 0) + 1
        
        entropy = 0.0
        for count in freq.values():
            p = count / len(s)
            entropy -= p * np.log2(p)
        
        return entropy
    
    def _calculate_ngram_entropy(self, s: str, n: int) -> float:
        """Calculate n-gram entropy"""
        if len(s) < n:
            return 0.0
        
        ngrams = [s[i:i+n] for i in range(len(s) - n + 1)]
        freq = {}
        for ng in ngrams:
            freq[ng] = freq.get(ng, 0) + 1
        
        entropy = 0.0
        total = len(ngrams)
        for count in freq.values():
            p = count / total
            entropy -= p * np.log2(p)
        
        return entropy
    
    def predict(self, domain: str) -> Tuple[bool, float, str]:
        """
        Predict if domain is used for tunneling
        Returns: (is_tunneling, score, threat_type)
        """
        features = self.extract_features(domain)
        
        # Rule-based detection
        entropy = features[7]  # entropy feature
        length = features[0]
        subdomain_count = features[1]
        
        score = 0.0
        threat_type = "benign"
        
        # High entropy indicates possible encoding
        if entropy > self.entropy_threshold:
            score += 0.3
        
        # Long domains are suspicious
        if length > self.length_threshold:
            score += 0.2
        
        # Many subdomains indicate possible tunneling
        if subdomain_count > self.subdomain_threshold:
            score += 0.2
        
        # High digit ratio indicates possible encoding
        digit_ratio = features[5]
        if digit_ratio > 0.3:
            score += 0.15
        
        # Low vowel ratio indicates possible encoding
        vowel_ratio = features[8]
        if vowel_ratio < 0.1:
            score += 0.15
        
        # Determine threat type
        is_tunneling = score > 0.5
        if is_tunneling:
            if entropy > 4.0 and digit_ratio > 0.4:
                threat_type = "dns_tunneling_encoded"
            elif subdomain_count > 6:
                threat_type = "dns_tunneling_exfiltration"
            else:
                threat_type = "dns_tunneling_suspicious"
        
        return is_tunneling, min(score, 1.0), threat_type


class DGADetector:
    """Domain Generation Algorithm (DGA) detection"""
    
    def __init__(self):
        self.model: Optional[any] = None
        self.is_fitted = False
        
        # Character frequency baseline (from legitimate domains)
        self.char_freq_baseline = {
            'e': 0.127, 't': 0.091, 'a': 0.082, 'o': 0.075, 'i': 0.070,
            'n': 0.067, 's': 0.063, 'h': 0.061, 'r': 0.060, 'd': 0.043,
            'l': 0.040, 'c': 0.028, 'u': 0.028, 'm': 0.024, 'w': 0.024,
        }
        
    def predict(self, domain: str) -> Tuple[bool, float]:
        """
        Predict if domain is DGA-generated
        Returns: (is_dga, score)
        """
        # Remove TLD for analysis
        parts = domain.lower().split('.')
        if len(parts) > 1:
            domain_part = '.'.join(parts[:-1])
        else:
            domain_part = domain.lower()
        
        score = 0.0
        
        # Length analysis
        if len(domain_part) > 20:
            score += 0.15
        
        # Character frequency deviation
        char_freq = {}
        for c in domain_part:
            if c.isalpha():
                char_freq[c] = char_freq.get(c, 0) + 1
        
        total_chars = sum(char_freq.values())
        if total_chars > 0:
            deviation = 0.0
            for char, expected in self.char_freq_baseline.items():
                actual = char_freq.get(char, 0) / total_chars
                deviation += abs(actual - expected)
            
            # High deviation indicates possible DGA
            if deviation > 0.5:
                score += 0.25
        
        # Entropy analysis
        entropy = self._calculate_entropy(domain_part)
        if entropy > 3.8:
            score += 0.2
        
        # Consecutive consonants
        max_consonants = self._max_consecutive_consonants(domain_part)
        if max_consonants > 4:
            score += 0.2
        
        # Digit presence
        digit_count = sum(1 for c in domain_part if c.isdigit())
        if digit_count > 3:
            score += 0.1
        
        # No vowels
        vowel_count = sum(1 for c in domain_part if c in 'aeiou')
        if vowel_count == 0 and len(domain_part) > 5:
            score += 0.1
        
        is_dga = score > 0.5
        return is_dga, min(score, 1.0)
    
    def _calculate_entropy(self, s: str) -> float:
        """Calculate Shannon entropy"""
        if not s:
            return 0.0
        
        freq = {}
        for c in s:
            freq[c] = freq.get(c, 0) + 1
        
        entropy = 0.0
        for count in freq.values():
            p = count / len(s)
            entropy -= p * np.log2(p)
        
        return entropy
    
    def _max_consecutive_consonants(self, s: str) -> int:
        """Find maximum consecutive consonants"""
        vowels = set('aeiou')
        max_count = 0
        current_count = 0
        
        for c in s.lower():
            if c.isalpha() and c not in vowels:
                current_count += 1
                max_count = max(max_count, current_count)
            else:
                current_count = 0
        
        return max_count


class TrafficClassifier:
    """Network traffic classification"""
    
    # Application categories
    CATEGORIES = {
        'web': ['http', 'https', 'web'],
        'streaming': ['video', 'audio', 'streaming', 'youtube', 'netflix'],
        'gaming': ['game', 'gaming'],
        'voip': ['voip', 'voice', 'sip', 'rtp'],
        'file_transfer': ['ftp', 'sftp', 'smb', 'nfs'],
        'email': ['smtp', 'imap', 'pop3', 'email'],
        'database': ['mysql', 'postgres', 'mongodb', 'redis'],
        'vpn': ['vpn', 'wireguard', 'openvpn', 'ipsec'],
        'malware': ['c2', 'malware', 'botnet'],
        'unknown': ['unknown'],
    }
    
    # Well-known ports
    PORT_APPS = {
        80: 'http',
        443: 'https',
        22: 'ssh',
        21: 'ftp',
        25: 'smtp',
        53: 'dns',
        110: 'pop3',
        143: 'imap',
        3306: 'mysql',
        5432: 'postgres',
        6379: 'redis',
        27017: 'mongodb',
        8080: 'http_proxy',
        8443: 'https_alt',
    }
    
    def __init__(self):
        self.model: Optional[any] = None
        self.is_fitted = False
    
    def classify(self, features: dict) -> Tuple[str, str, float]:
        """
        Classify traffic based on features
        Returns: (application, category, confidence)
        """
        # Port-based classification
        dst_port = features.get('dst_port', 0)
        if dst_port in self.PORT_APPS:
            app = self.PORT_APPS[dst_port]
            category = self._get_category(app)
            return app, category, 0.9
        
        # Protocol-based classification
        protocol = features.get('protocol', '').lower()
        if protocol == 'tcp':
            # Analyze payload characteristics
            payload_entropy = features.get('payload_entropy', 0)
            
            if payload_entropy > 7.5:
                # High entropy suggests encryption
                return 'encrypted', 'unknown', 0.7
            elif payload_entropy < 4.0:
                # Low entropy suggests text-based protocol
                return 'text_protocol', 'unknown', 0.6
        
        elif protocol == 'udp':
            # Check for common UDP applications
            if dst_port == 53:
                return 'dns', 'web', 0.95
            elif dst_port in [67, 68]:
                return 'dhcp', 'network', 0.95
            elif dst_port == 123:
                return 'ntp', 'network', 0.95
            elif dst_port in range(16384, 32768):
                return 'rtp', 'voip', 0.7
        
        return 'unknown', 'unknown', 0.3
    
    def _get_category(self, app: str) -> str:
        """Get category for an application"""
        for category, apps in self.CATEGORIES.items():
            if app.lower() in apps:
                return category
        return 'unknown'


class MLInferenceServicer:
    """gRPC servicer for ML inference"""
    
    def __init__(self):
        self.model_manager = ModelManager()
        self.anomaly_detector = AnomalyDetector()
        self.dns_detector = DNSTunnelingDetector()
        self.dga_detector = DGADetector()
        self.traffic_classifier = TrafficClassifier()
        
        # Initialize with default models if available
        self._load_default_models()
    
    def _load_default_models(self):
        """Load default models from model directory"""
        model_dir = os.environ.get('MODEL_DIR', './models')
        
        if os.path.exists(model_dir):
            for filename in os.listdir(model_dir):
                filepath = os.path.join(model_dir, filename)
                name = os.path.splitext(filename)[0]
                
                if filename.endswith('.onnx'):
                    self.model_manager.load_onnx_model(name, filepath)
                elif filename.endswith('.joblib'):
                    if not filename.endswith('_scaler.joblib'):
                        self.model_manager.load_sklearn_model(name, filepath)
    
    def predict_flow(self, flow_id: str, features: np.ndarray, model_name: str) -> dict:
        """Predict flow classification"""
        try:
            result, latency = self.model_manager.predict(model_name, features)
            
            # Get predicted class
            if result.ndim > 1:
                class_idx = np.argmax(result[0])
                confidence = float(result[0][class_idx])
                probabilities = result[0].tolist()
            else:
                class_idx = int(result[0])
                confidence = 1.0
                probabilities = [confidence]
            
            return {
                'flow_id': flow_id,
                'label': str(class_idx),
                'confidence': confidence,
                'probabilities': probabilities,
                'latency_ms': latency,
            }
        except Exception as e:
            logger.error(f"Flow prediction error: {e}")
            return {
                'flow_id': flow_id,
                'label': 'error',
                'confidence': 0.0,
                'probabilities': [],
                'latency_ms': 0.0,
            }
    
    def detect_anomaly(self, entity_id: str, features: np.ndarray) -> dict:
        """Detect anomalies in features"""
        try:
            if not self.anomaly_detector.is_fitted:
                # Use simple threshold-based detection
                mean = np.mean(features)
                std = np.std(features)
                z_scores = np.abs((features - mean) / (std + 1e-10))
                anomaly_score = float(np.max(z_scores))
                is_anomaly = anomaly_score > 3.0
            else:
                is_anomaly, scores = self.anomaly_detector.predict(features.reshape(1, -1))
                anomaly_score = float(scores[0])
                is_anomaly = bool(is_anomaly[0])
            
            return {
                'entity_id': entity_id,
                'is_anomaly': is_anomaly,
                'anomaly_score': anomaly_score,
                'threshold': self.anomaly_detector.threshold if self.anomaly_detector.is_fitted else 3.0,
            }
        except Exception as e:
            logger.error(f"Anomaly detection error: {e}")
            return {
                'entity_id': entity_id,
                'is_anomaly': False,
                'anomaly_score': 0.0,
                'threshold': 0.0,
            }
    
    def predict_dns(self, query_id: str, domain: str) -> dict:
        """Predict DNS tunneling and DGA"""
        try:
            is_tunneling, tunnel_score, threat_type = self.dns_detector.predict(domain)
            is_dga, dga_score = self.dga_detector.predict(domain)
            
            return {
                'query_id': query_id,
                'is_tunneling': is_tunneling,
                'is_dga': is_dga,
                'tunneling_score': tunnel_score,
                'dga_score': dga_score,
                'threat_type': threat_type if is_tunneling else ('dga' if is_dga else 'benign'),
                'confidence': max(tunnel_score, dga_score),
            }
        except Exception as e:
            logger.error(f"DNS prediction error: {e}")
            return {
                'query_id': query_id,
                'is_tunneling': False,
                'is_dga': False,
                'tunneling_score': 0.0,
                'dga_score': 0.0,
                'threat_type': 'error',
                'confidence': 0.0,
            }
    
    def classify_traffic(self, flow_id: str, features: dict) -> dict:
        """Classify network traffic"""
        try:
            app, category, confidence = self.traffic_classifier.classify(features)
            
            return {
                'flow_id': flow_id,
                'application': app,
                'category': category,
                'confidence': confidence,
            }
        except Exception as e:
            logger.error(f"Traffic classification error: {e}")
            return {
                'flow_id': flow_id,
                'application': 'unknown',
                'category': 'unknown',
                'confidence': 0.0,
            }
    
    def health_check(self) -> dict:
        """Check service health"""
        model_status = {name: True for name in self.model_manager.models}
        
        return {
            'healthy': True,
            'status': 'running',
            'uptime_seconds': int(self.model_manager.get_uptime()),
            'model_status': model_status,
            'gpu_memory_used_mb': 0.0,  # Would need GPU monitoring
            'cpu_usage_percent': 0.0,   # Would need CPU monitoring
        }


def serve(port: int = 50051):
    """Start the gRPC server"""
    server = grpc.server(
        futures.ThreadPoolExecutor(max_workers=10),
        options=[
            ('grpc.max_send_message_length', 100 * 1024 * 1024),
            ('grpc.max_receive_message_length', 100 * 1024 * 1024),
        ]
    )
    
    servicer = MLInferenceServicer()
    
    # Note: In production, you would register the generated servicer here
    # ml_inference_pb2_grpc.add_MLInferenceServicer_to_server(servicer, server)
    
    # Enable reflection for debugging
    SERVICE_NAMES = (
        # ml_inference_pb2.DESCRIPTOR.services_by_name['MLInference'].full_name,
        reflection.SERVICE_NAME,
    )
    reflection.enable_server_reflection(SERVICE_NAMES, server)
    
    server.add_insecure_port(f'[::]:{port}')
    server.start()
    
    logger.info(f"ML Inference server started on port {port}")
    
    # Handle shutdown
    def shutdown(signum, frame):
        logger.info("Shutting down server...")
        server.stop(5)
        sys.exit(0)
    
    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)
    
    server.wait_for_termination()


if __name__ == '__main__':
    port = int(os.environ.get('ML_SIDECAR_PORT', 50051))
    serve(port)
