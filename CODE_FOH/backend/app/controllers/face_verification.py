import face_recognition
import cv2


def verify_face(saved_image_path, captured_image_path):
    saved_image = face_recognition.load_image_file(saved_image_path)
    saved_face_encoding = face_recognition.face_encodings(saved_image)

    captured_image = face_recognition.load_image_file(captured_image_path)
    captured_face_encoding = face_recognition.face_encodings(captured_image)

    if not saved_face_encoding or not captured_face_encoding:
        return False

    matches = face_recognition.compare_faces(
        saved_face_encoding, captured_face_encoding[0])

    return matches[0]
