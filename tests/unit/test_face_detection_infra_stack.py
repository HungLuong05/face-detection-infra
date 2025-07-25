import aws_cdk as core
import aws_cdk.assertions as assertions

from face_detection_infra.face_detection_infra_stack import FaceDetectionInfraStack

# example tests. To run these tests, uncomment this file along with the example
# resource in face_detection_infra/face_detection_infra_stack.py
def test_sqs_queue_created():
    app = core.App()
    stack = FaceDetectionInfraStack(app, "face-detection-infra")
    template = assertions.Template.from_stack(stack)

#     template.has_resource_properties("AWS::SQS::Queue", {
#         "VisibilityTimeout": 300
#     })
