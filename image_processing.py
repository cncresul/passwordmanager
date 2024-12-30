# utils/image_processing.py
import cv2
import numpy as np

def extract_features(image_path):
    """
    Görüntüden özellikler çıkarır.

    Args:
        image_path (str): Görüntü dosyasının yolu.

    Returns:
        numpy.ndarray: Özellik vektörü.
    """
    img = cv2.imread(image_path)
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    edges = cv2.Canny(gray, 100, 200)
    hist = cv2.calcHist([img], [0, 1, 2], None, [8, 8, 8], [0, 256, 0, 256, 0, 256])
    features = np.concatenate((hist.flatten(), edges.flatten()))
    return features