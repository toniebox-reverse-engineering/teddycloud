import { useTranslation } from "react-i18next";
import { useField } from "formik";
import FormItem from "antd/es/form/FormItem";
import { Switch, SwitchProps } from "antd";

type SwitchFieldProps = {
  name: string;
  label?: string;
  valueConverter?: {
    fromValueToBoolean: (fromValue: any) => boolean | undefined;
    fromBooleanToValue: (booleanValue?: boolean) => any;
  };
};

export const SwitchField = (props: SwitchFieldProps & SwitchProps) => {
  const { t } = useTranslation();
  const { name, label, valueConverter, ...switchProps } = props;
  const [field, meta, { setValue }] = useField(name!);

  const hasFeedback = !!(meta.touched && meta.error);
  const help = meta.touched && meta.error && t(meta.error);
  const validateStatus = meta.touched && meta.error ? "error" : undefined;

  const isChecked = valueConverter
    ? valueConverter.fromValueToBoolean(meta.value)
    : meta.value;

  return (
    <FormItem
      help={hasFeedback ? help : undefined}
      validateStatus={validateStatus}
      label={label}
    >
      <Switch
        {...switchProps}
        {...field}
        checked={isChecked}
        onChange={(value: boolean) => {
          //TODO: Fix fetch and replace with apiClient
          fetch(`http://localhost/api/set/${name}`, {
            method: "POST",
            body: value.toString(),
            headers: {
              "Content-Type": "text/plain",
            },
          });

          setValue(value);
        }}
      />
    </FormItem>
  );
};
