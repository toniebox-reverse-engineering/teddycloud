import { useTranslation } from "react-i18next";
import { useField } from "formik";
import FormItem from "antd/es/form/FormItem";
import { InputNumber, InputNumberProps } from "antd";

type InputNumberFieldProps = {
  name: string;
  label?: string;
};

const InputNumberField = (props: InputNumberFieldProps & InputNumberProps) => {
  const { t } = useTranslation();
  const { name, label, ...inputNumberProps } = props;
  const [field, meta, helpers] = useField<number | undefined>(name!);

  const hasFeedback = !!(meta.touched && meta.error);
  const help = meta.touched && meta.error && t(meta.error);
  const validateStatus = meta.touched && meta.error ? "error" : undefined;

  return (
    <FormItem
      help={hasFeedback ? help : undefined}
      validateStatus={validateStatus}
      label={label}
    >
      <InputNumber
        {...inputNumberProps}
        {...field}
        onChange={(value: number | undefined | string | null) => {
          helpers.setValue(value === null ? undefined : Number(value));
        }}
        onBlur={() => helpers.setTouched(true)}
      />
    </FormItem>
  );
};

export { InputNumberField };
