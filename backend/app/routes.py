from flask import Blueprint, request, jsonify
from flask_cors import cross_origin
from app.model import analyze_url
from .model import logger
import traceback

routes = Blueprint('routes', __name__)

@routes.route('/predict', methods=['OPTIONS', 'POST'])
@cross_origin()
def predict():
    # Import mongo inside the route to avoid circular import
    from app import mongo

    if request.method == 'OPTIONS':
        return jsonify({}), 200
    try:
        data = request.get_json()
        logger.debug(f"Incoming JSON data: {data}")

        url = data.get('url')
        if not url:
            logger.warning("URL not provided in request")
            return jsonify({'error': 'URL is required'}), 400

        result = analyze_url(url)
        logger.debug(f"Prediction result: {result}")

        # Log the prediction result to MongoDB
        try:
            predictions_collection = mongo.db.predictions
            predictions_collection.insert_one({
                'url': result['url'],
                'domain': result['domain'],
                'probability': result['probability'],
                'verdict': result['verdict'],
                'timestamp': request.date.isoformat() if request.date else None
            })
            logger.info(f"Prediction logged to MongoDB for URL: {url}")
        except Exception as e:
            logger.warning(f"Failed to log prediction to MongoDB: {str(e)}")

        return jsonify(result), 200

    except Exception as e:
        logger.error(f"Error in /predict route: {str(e)}\n{traceback.format_exc()}")
        return jsonify({'error': str(e)}), 500

@routes.route('/test', methods=['GET'])
@cross_origin()
def test():
    logger.info("Test endpoint accessed")
    return jsonify({'message': 'Backend is running'}), 200